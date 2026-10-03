package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/binary"
	"errors"
	"net/http"
	"strings"
	"time"
)

type deviceRequest struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type accountRequest struct {
	InviteCode         string        `json:"inviteCode"`
	AccountID          string        `json:"accountId"`
	EnrollmentVerifier string        `json:"enrollmentVerifier"`
	Device             deviceRequest `json:"device"`
}

type enrollRequest struct {
	AccountID        string        `json:"accountId"`
	EnrollmentSecret string        `json:"enrollmentSecret"`
	Device           deviceRequest `json:"device"`
}

type tokenResponse struct {
	AccessToken      string `json:"accessToken"`
	AccessExpiresAt  int64  `json:"accessExpiresAt"`
	RefreshToken     string `json:"refreshToken"`
	RefreshExpiresAt int64  `json:"refreshExpiresAt"`
}

type challengeRequest struct {
	AccountID string `json:"accountId"`
	DeviceID  string `json:"deviceId"`
}

type challengeResponse struct {
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	ExpiresAt   int64  `json:"expiresAt"`
}

type exchangeRequest struct {
	ChallengeID string `json:"challengeId"`
	Signature   string `json:"signature"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

func validateDevice(value deviceRequest) ([]byte, error) {
	if !validOpaqueID(value.ID) {
		return nil, errors.New("device id must be 128-bit lowercase hex")
	}
	value.Name = strings.TrimSpace(value.Name)
	if len(value.Name) < 1 || len(value.Name) > 100 {
		return nil, errors.New("device name must contain 1 to 100 characters")
	}
	publicKey, err := rawBase64.DecodeString(value.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("device public key must be a base64url Ed25519 key")
	}
	return publicKey, nil
}

func (a *API) createAccount(response http.ResponseWriter, request *http.Request) {
	var input accountRequest
	if !a.decodeJSON(response, request, &input) {
		return
	}
	if !validOpaqueID(input.AccountID) {
		a.writeError(response, http.StatusBadRequest, "invalid_account", "account id must be 128-bit lowercase hex")
		return
	}
	verifier, err := rawBase64.DecodeString(input.EnrollmentVerifier)
	if err != nil || len(verifier) != sha256.Size {
		a.writeError(response, http.StatusBadRequest, "invalid_verifier", "enrollment verifier must be 32 bytes")
		return
	}
	publicKey, err := validateDevice(input.Device)
	if err != nil {
		a.writeError(response, http.StatusBadRequest, "invalid_device", err.Error())
		return
	}
	transaction, err := a.store.db.BeginTx(request.Context(), nil)
	if err != nil {
		a.serverError(response, err)
		return
	}
	defer transaction.Rollback()
	if err := consumeInvite(request.Context(), transaction, input.InviteCode); err != nil {
		a.writeError(response, http.StatusForbidden, "invalid_invite", "invite is invalid, expired, or already used")
		return
	}
	now := unixNow()
	if _, err := transaction.ExecContext(request.Context(), `INSERT INTO accounts(id, enrollment_verifier, created_at) VALUES(?, ?, ?)`, input.AccountID, verifier, now); err != nil {
		a.writeError(response, http.StatusConflict, "account_exists", "account id is already registered")
		return
	}
	if _, err := transaction.ExecContext(request.Context(), `INSERT INTO devices(id, account_id, name, public_key, created_at) VALUES(?, ?, ?, ?, ?)`, input.Device.ID, input.AccountID, strings.TrimSpace(input.Device.Name), publicKey, now); err != nil {
		a.serverError(response, err)
		return
	}
	tokens, err := issueNewFamily(request.Context(), transaction, input.AccountID, input.Device.ID)
	if err != nil {
		a.serverError(response, err)
		return
	}
	if err := transaction.Commit(); err != nil {
		a.serverError(response, err)
		return
	}
	a.writeJSON(response, http.StatusCreated, map[string]any{"accountId": input.AccountID, "tokens": tokens})
}

func consumeInvite(ctx context.Context, transaction *sql.Tx, code string) error {
	if len(code) < 20 || len(code) > 200 {
		return errors.New("invalid invite")
	}
	hash := tokenHash(code)
	var expiresAt int64
	var uses int
	if err := transaction.QueryRowContext(ctx, `SELECT expires_at, remaining_uses FROM invites WHERE hash = ?`, hash).Scan(&expiresAt, &uses); err != nil {
		return err
	}
	if expiresAt < unixNow() || uses < 1 {
		return errors.New("expired invite")
	}
	if uses == 1 {
		_, _ = transaction.ExecContext(ctx, `DELETE FROM invites WHERE hash = ?`, hash)
	} else {
		_, _ = transaction.ExecContext(ctx, `UPDATE invites SET remaining_uses = remaining_uses - 1 WHERE hash = ?`, hash)
	}
	return nil
}

func (a *API) enrollDevice(response http.ResponseWriter, request *http.Request) {
	var input enrollRequest
	if !a.decodeJSON(response, request, &input) {
		return
	}
	if !validOpaqueID(input.AccountID) {
		a.writeError(response, http.StatusBadRequest, "invalid_account", "invalid account id")
		return
	}
	secret, err := rawBase64.DecodeString(input.EnrollmentSecret)
	if err != nil || len(secret) != 32 {
		a.writeError(response, http.StatusBadRequest, "invalid_recovery", "invalid enrollment secret")
		return
	}
	publicKey, err := validateDevice(input.Device)
	if err != nil {
		a.writeError(response, http.StatusBadRequest, "invalid_device", err.Error())
		return
	}
	provided := sha256.Sum256(secret)
	transaction, err := a.store.db.BeginTx(request.Context(), nil)
	if err != nil {
		a.serverError(response, err)
		return
	}
	defer transaction.Rollback()
	var stored []byte
	if err := transaction.QueryRowContext(request.Context(), `SELECT enrollment_verifier FROM accounts WHERE id = ?`, input.AccountID).Scan(&stored); err != nil || len(stored) != sha256.Size || subtle.ConstantTimeCompare(stored, provided[:]) != 1 {
		a.writeError(response, http.StatusUnauthorized, "invalid_recovery", "recovery secret is invalid")
		return
	}
	now := unixNow()
	if _, err := transaction.ExecContext(request.Context(), `INSERT INTO devices(id, account_id, name, public_key, created_at) VALUES(?, ?, ?, ?, ?)`, input.Device.ID, input.AccountID, strings.TrimSpace(input.Device.Name), publicKey, now); err != nil {
		a.writeError(response, http.StatusConflict, "device_exists", "device id is already registered")
		return
	}
	tokens, err := issueNewFamily(request.Context(), transaction, input.AccountID, input.Device.ID)
	if err != nil {
		a.serverError(response, err)
		return
	}
	if err := transaction.Commit(); err != nil {
		a.serverError(response, err)
		return
	}
	a.writeJSON(response, http.StatusCreated, tokens)
}

func (a *API) createChallenge(response http.ResponseWriter, request *http.Request) {
	var input challengeRequest
	if !a.decodeJSON(response, request, &input) {
		return
	}
	if !validOpaqueID(input.AccountID) || !validOpaqueID(input.DeviceID) {
		a.writeError(response, http.StatusBadRequest, "invalid_device", "invalid account or device id")
		return
	}
	var active int
	if err := a.store.db.QueryRowContext(request.Context(), `SELECT COUNT(*) FROM devices WHERE id = ? AND account_id = ? AND revoked_at IS NULL`, input.DeviceID, input.AccountID).Scan(&active); err != nil || active != 1 {
		a.writeError(response, http.StatusUnauthorized, "unknown_device", "device is not enrolled")
		return
	}
	challengeID, err := randomToken(24)
	if err != nil {
		a.serverError(response, err)
		return
	}
	nonce, err := randomBytes(32)
	if err != nil {
		a.serverError(response, err)
		return
	}
	expiresAt := time.Now().Add(ChallengeLifetime).Unix()
	if _, err := a.store.db.ExecContext(request.Context(), `INSERT INTO challenges(id, account_id, device_id, nonce, expires_at) VALUES(?, ?, ?, ?, ?)`, challengeID, input.AccountID, input.DeviceID, nonce, expiresAt); err != nil {
		a.serverError(response, err)
		return
	}
	a.writeJSON(response, http.StatusCreated, challengeResponse{ChallengeID: challengeID, Nonce: rawBase64.EncodeToString(nonce), ExpiresAt: expiresAt})
}

func authMessage(instanceID, accountID, deviceID, challengeID string, nonce []byte) []byte {
	parts := [][]byte{[]byte("phone-ledger-auth-v1"), []byte(instanceID), []byte(accountID), []byte(deviceID), []byte(challengeID), nonce}
	length := 0
	for _, part := range parts {
		length += 4 + len(part)
	}
	message := make([]byte, 0, length)
	buffer := make([]byte, 4)
	for _, part := range parts {
		binary.BigEndian.PutUint32(buffer, uint32(len(part)))
		message = append(message, buffer...)
		message = append(message, part...)
	}
	return message
}

func (a *API) exchangeChallenge(response http.ResponseWriter, request *http.Request) {
	var input exchangeRequest
	if !a.decodeJSON(response, request, &input) {
		return
	}
	signature, err := rawBase64.DecodeString(input.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		a.writeError(response, http.StatusBadRequest, "invalid_signature", "invalid device signature")
		return
	}
	transaction, err := a.store.db.BeginTx(request.Context(), nil)
	if err != nil {
		a.serverError(response, err)
		return
	}
	defer transaction.Rollback()
	var accountID, deviceID string
	var nonce, publicKey []byte
	var expiresAt int64
	var usedAt sql.NullInt64
	err = transaction.QueryRowContext(request.Context(), `SELECT c.account_id, c.device_id, c.nonce, c.expires_at, c.used_at, d.public_key FROM challenges c JOIN devices d ON d.id = c.device_id AND d.account_id = c.account_id WHERE c.id = ? AND d.revoked_at IS NULL`, input.ChallengeID).Scan(&accountID, &deviceID, &nonce, &expiresAt, &usedAt, &publicKey)
	if err != nil || usedAt.Valid || expiresAt < unixNow() || !ed25519.Verify(publicKey, authMessage(a.store.InstanceID(), accountID, deviceID, input.ChallengeID, nonce), signature) {
		a.writeError(response, http.StatusUnauthorized, "invalid_challenge", "challenge is invalid, expired, or already used")
		return
	}
	if _, err := transaction.ExecContext(request.Context(), `UPDATE challenges SET used_at = ? WHERE id = ? AND used_at IS NULL`, unixNow(), input.ChallengeID); err != nil {
		a.serverError(response, err)
		return
	}
	tokens, err := issueNewFamily(request.Context(), transaction, accountID, deviceID)
	if err != nil {
		a.serverError(response, err)
		return
	}
	if err := transaction.Commit(); err != nil {
		a.serverError(response, err)
		return
	}
	a.writeJSON(response, http.StatusOK, tokens)
}

func issueNewFamily(ctx context.Context, transaction *sql.Tx, accountID, deviceID string) (tokenResponse, error) {
	familyID, err := newUUID()
	if err != nil {
		return tokenResponse{}, err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO token_families(id, account_id, device_id) VALUES(?, ?, ?)`, familyID, accountID, deviceID); err != nil {
		return tokenResponse{}, err
	}
	return issueTokenPair(ctx, transaction, familyID)
}

func issueTokenPair(ctx context.Context, transaction *sql.Tx, familyID string) (tokenResponse, error) {
	access, err := randomToken(32)
	if err != nil {
		return tokenResponse{}, err
	}
	refresh, err := randomToken(32)
	if err != nil {
		return tokenResponse{}, err
	}
	now := time.Now()
	accessExpiry := now.Add(AccessTokenLifetime).Unix()
	refreshExpiry := now.Add(RefreshTokenLifetime).Unix()
	if _, err := transaction.ExecContext(ctx, `INSERT INTO tokens(hash, family_id, kind, expires_at) VALUES(?, ?, 'access', ?), (?, ?, 'refresh', ?)`, tokenHash(access), familyID, accessExpiry, tokenHash(refresh), familyID, refreshExpiry); err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{AccessToken: access, AccessExpiresAt: accessExpiry, RefreshToken: refresh, RefreshExpiresAt: refreshExpiry}, nil
}

func (a *API) authenticate(ctx context.Context, token string) (principal, error) {
	if len(token) < 40 || len(token) > 100 {
		return principal{}, errors.New("invalid token")
	}
	var identity principal
	err := a.store.db.QueryRowContext(ctx, `SELECT f.account_id, f.device_id, f.id FROM tokens t JOIN token_families f ON f.id = t.family_id JOIN devices d ON d.id = f.device_id AND d.account_id = f.account_id WHERE t.hash = ? AND t.kind = 'access' AND t.expires_at >= ? AND t.revoked_at IS NULL AND f.revoked_at IS NULL AND d.revoked_at IS NULL`, tokenHash(token), unixNow()).Scan(&identity.AccountID, &identity.DeviceID, &identity.FamilyID)
	if err != nil {
		return principal{}, err
	}
	_, _ = a.store.db.ExecContext(ctx, `UPDATE devices SET last_seen_at = ? WHERE id = ? AND account_id = ?`, unixNow(), identity.DeviceID, identity.AccountID)
	return identity, nil
}

func (a *API) refreshTokens(response http.ResponseWriter, request *http.Request) {
	var input refreshRequest
	if !a.decodeJSON(response, request, &input) {
		return
	}
	transaction, err := a.store.db.BeginTx(request.Context(), nil)
	if err != nil {
		a.serverError(response, err)
		return
	}
	defer transaction.Rollback()
	var familyID string
	var expiresAt int64
	var rotatedAt, revokedAt, familyRevoked, deviceRevoked sql.NullInt64
	err = transaction.QueryRowContext(request.Context(), `SELECT t.family_id, t.expires_at, t.rotated_at, t.revoked_at, f.revoked_at, d.revoked_at FROM tokens t JOIN token_families f ON f.id = t.family_id JOIN devices d ON d.id = f.device_id AND d.account_id = f.account_id WHERE t.hash = ? AND t.kind = 'refresh'`, tokenHash(input.RefreshToken)).Scan(&familyID, &expiresAt, &rotatedAt, &revokedAt, &familyRevoked, &deviceRevoked)
	if err != nil {
		a.writeError(response, http.StatusUnauthorized, "invalid_refresh_token", "refresh token is invalid or expired")
		return
	}
	if rotatedAt.Valid || revokedAt.Valid {
		_, _ = transaction.ExecContext(request.Context(), `UPDATE token_families SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, unixNow(), familyID)
		_ = transaction.Commit()
		a.writeError(response, http.StatusUnauthorized, "refresh_reuse", "refresh token reuse detected; session revoked")
		return
	}
	if expiresAt < unixNow() || familyRevoked.Valid || deviceRevoked.Valid {
		a.writeError(response, http.StatusUnauthorized, "invalid_refresh_token", "refresh token is invalid or expired")
		return
	}
	if _, err := transaction.ExecContext(request.Context(), `UPDATE tokens SET rotated_at = ? WHERE hash = ?`, unixNow(), tokenHash(input.RefreshToken)); err != nil {
		a.serverError(response, err)
		return
	}
	tokens, err := issueTokenPair(request.Context(), transaction, familyID)
	if err != nil {
		a.serverError(response, err)
		return
	}
	if err := transaction.Commit(); err != nil {
		a.serverError(response, err)
		return
	}
	a.writeJSON(response, http.StatusOK, tokens)
}

func (a *API) serverError(response http.ResponseWriter, err error) {
	a.logger.Error("request failed", "error", err)
	a.writeError(response, http.StatusInternalServerError, "internal_error", "request could not be completed")
}

func (a *API) listDevices(response http.ResponseWriter, request *http.Request) {
	identity := requestPrincipal(request)
	rows, err := a.store.db.QueryContext(request.Context(), `SELECT id, name, created_at, last_seen_at, revoked_at FROM devices WHERE account_id = ? ORDER BY created_at, id`, identity.AccountID)
	if err != nil {
		a.serverError(response, err)
		return
	}
	defer rows.Close()
	type device struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		CreatedAt  int64  `json:"createdAt"`
		LastSeenAt *int64 `json:"lastSeenAt"`
		RevokedAt  *int64 `json:"revokedAt"`
		Current    bool   `json:"current"`
	}
	devices := make([]device, 0)
	for rows.Next() {
		var value device
		var lastSeen, revoked sql.NullInt64
		if err := rows.Scan(&value.ID, &value.Name, &value.CreatedAt, &lastSeen, &revoked); err != nil {
			a.serverError(response, err)
			return
		}
		if lastSeen.Valid {
			value.LastSeenAt = &lastSeen.Int64
		}
		if revoked.Valid {
			value.RevokedAt = &revoked.Int64
		}
		value.Current = value.ID == identity.DeviceID
		devices = append(devices, value)
	}
	a.writeJSON(response, http.StatusOK, map[string]any{"devices": devices})
}

func (a *API) revokeDevice(response http.ResponseWriter, request *http.Request) {
	identity := requestPrincipal(request)
	deviceID := request.PathValue("deviceID")
	if !validOpaqueID(deviceID) {
		a.writeError(response, http.StatusBadRequest, "invalid_device", "invalid device id")
		return
	}
	transaction, err := a.store.db.BeginTx(request.Context(), nil)
	if err != nil {
		a.serverError(response, err)
		return
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(request.Context(), `UPDATE devices SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ? AND account_id = ?`, unixNow(), deviceID, identity.AccountID)
	if err != nil {
		a.serverError(response, err)
		return
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		a.writeError(response, http.StatusNotFound, "device_not_found", "device was not found")
		return
	}
	_, _ = transaction.ExecContext(request.Context(), `UPDATE token_families SET revoked_at = COALESCE(revoked_at, ?) WHERE account_id = ? AND device_id = ?`, unixNow(), identity.AccountID, deviceID)
	if err := transaction.Commit(); err != nil {
		a.serverError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
