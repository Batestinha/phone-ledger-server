package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
)

func revisionETag(revision int64) string { return fmt.Sprintf("\"%d\"", revision) }

func parseBaseRevision(request *http.Request) (int64, error) {
	value := strings.TrimSpace(request.Header.Get("If-Match"))
	if len(value) < 3 || value[0] != '"' || value[len(value)-1] != '"' {
		return 0, errors.New("If-Match must contain a quoted revision")
	}
	revision, err := strconv.ParseInt(value[1:len(value)-1], 10, 64)
	if err != nil || revision < 0 || revision >= math.MaxInt64 {
		return 0, errors.New("If-Match contains an invalid revision")
	}
	return revision, nil
}

func readVaultBody(response http.ResponseWriter, request *http.Request) ([]byte, []byte, error) {
	if request.Header.Get("Content-Type") != "application/octet-stream" {
		return nil, nil, errors.New("Content-Type must be application/octet-stream")
	}
	request.Body = http.MaxBytesReader(response, request.Body, MaxVaultBytes)
	blob, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, nil, errors.New("vault exceeds the maximum size")
	}
	if len(blob) < 29 {
		return nil, nil, errors.New("encrypted vault is too short")
	}
	digest := sha256.Sum256(blob)
	provided, err := rawBase64.DecodeString(request.Header.Get("X-Content-SHA256"))
	if err != nil || len(provided) != sha256.Size || subtle.ConstantTimeCompare(provided, digest[:]) != 1 {
		return nil, nil, errors.New("vault digest is missing or incorrect")
	}
	return blob, digest[:], nil
}

func (a *API) getVault(response http.ResponseWriter, request *http.Request) {
	identity := requestPrincipal(request)
	var revision int64
	var format int
	var blob, digest []byte
	err := a.store.db.QueryRowContext(request.Context(), `SELECT revision, format, blob, digest FROM vaults WHERE account_id = ? ORDER BY revision DESC LIMIT 1`, identity.AccountID).Scan(&revision, &format, &blob, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		response.Header().Set("ETag", revisionETag(0))
		response.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		a.serverError(response, err)
		return
	}
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("ETag", revisionETag(revision))
	response.Header().Set("X-Phone-Ledger-Format", strconv.Itoa(format))
	response.Header().Set("X-Content-SHA256", rawBase64.EncodeToString(digest))
	response.Header().Set("Content-Length", strconv.Itoa(len(blob)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(blob)
}

func (a *API) putVault(response http.ResponseWriter, request *http.Request) {
	identity := requestPrincipal(request)
	baseRevision, err := parseBaseRevision(request)
	if err != nil {
		a.writeError(response, http.StatusBadRequest, "invalid_revision", err.Error())
		return
	}
	format, err := strconv.Atoi(request.Header.Get("X-Phone-Ledger-Format"))
	if err != nil || format != ProtocolVersion {
		a.writeError(response, http.StatusBadRequest, "unsupported_format", "vault format is unsupported")
		return
	}
	blob, digest, err := readVaultBody(response, request)
	if err != nil {
		a.writeError(response, http.StatusBadRequest, "invalid_vault", err.Error())
		return
	}
	transaction, err := a.store.db.BeginTx(request.Context(), nil)
	if err != nil {
		a.serverError(response, err)
		return
	}
	defer transaction.Rollback()
	newRevision, rollbackRecovery, currentRevision, err := a.insertVault(request.Context(), transaction, identity.AccountID, baseRevision, format, blob, digest)
	if errors.Is(err, errRevisionConflict) {
		response.Header().Set("ETag", revisionETag(currentRevision))
		a.writeJSON(response, http.StatusConflict, map[string]any{"code": "revision_conflict", "currentRevision": currentRevision})
		return
	}
	if err != nil {
		a.serverError(response, err)
		return
	}
	if err := transaction.Commit(); err != nil {
		a.serverError(response, err)
		return
	}
	response.Header().Set("ETag", revisionETag(newRevision))
	if rollbackRecovery {
		response.Header().Set("X-Phone-Ledger-Rollback-Recovery", "true")
		a.logger.Warn("accepted client rollback recovery", "server_revision", currentRevision, "client_revision", baseRevision)
	}
	response.WriteHeader(http.StatusNoContent)
}

var errRevisionConflict = errors.New("revision conflict")

func (a *API) insertVault(ctx context.Context, transaction *sql.Tx, accountID string, baseRevision int64, format int, blob, digest []byte) (newRevision int64, rollbackRecovery bool, currentRevision int64, err error) {
	if err = transaction.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) FROM vaults WHERE account_id = ?`, accountID).Scan(&currentRevision); err != nil {
		return 0, false, 0, err
	}
	if baseRevision < currentRevision {
		return 0, false, currentRevision, errRevisionConflict
	}
	newRevision = baseRevision + 1
	rollbackRecovery = baseRevision > currentRevision
	if _, err = transaction.ExecContext(ctx, `INSERT INTO vaults(account_id, revision, format, blob, digest, created_at) VALUES(?, ?, ?, ?, ?, ?)`, accountID, newRevision, format, blob, digest, unixNow()); err != nil {
		return 0, false, currentRevision, err
	}
	if _, err = transaction.ExecContext(ctx, `DELETE FROM vaults WHERE account_id = ? AND revision NOT IN (SELECT revision FROM vaults WHERE account_id = ? ORDER BY revision DESC LIMIT ?)`, accountID, accountID, a.store.retention); err != nil {
		return 0, false, currentRevision, err
	}
	return newRevision, rollbackRecovery, currentRevision, nil
}

func (a *API) rotateRecovery(response http.ResponseWriter, request *http.Request) {
	identity := requestPrincipal(request)
	baseRevision, err := parseBaseRevision(request)
	if err != nil {
		a.writeError(response, http.StatusBadRequest, "invalid_revision", err.Error())
		return
	}
	verifier, err := rawBase64.DecodeString(request.Header.Get("X-Phone-Ledger-Enrollment-Verifier"))
	if err != nil || len(verifier) != sha256.Size {
		a.writeError(response, http.StatusBadRequest, "invalid_verifier", "new enrollment verifier must be 32 bytes")
		return
	}
	format, err := strconv.Atoi(request.Header.Get("X-Phone-Ledger-Format"))
	if err != nil || format != ProtocolVersion {
		a.writeError(response, http.StatusBadRequest, "unsupported_format", "vault format is unsupported")
		return
	}
	blob, digest, err := readVaultBody(response, request)
	if err != nil {
		a.writeError(response, http.StatusBadRequest, "invalid_vault", err.Error())
		return
	}
	transaction, err := a.store.db.BeginTx(request.Context(), nil)
	if err != nil {
		a.serverError(response, err)
		return
	}
	defer transaction.Rollback()
	newRevision, _, currentRevision, err := a.insertVault(request.Context(), transaction, identity.AccountID, baseRevision, format, blob, digest)
	if errors.Is(err, errRevisionConflict) {
		response.Header().Set("ETag", revisionETag(currentRevision))
		a.writeJSON(response, http.StatusConflict, map[string]any{"code": "revision_conflict", "currentRevision": currentRevision})
		return
	}
	if err != nil {
		a.serverError(response, err)
		return
	}
	if _, err := transaction.ExecContext(request.Context(), `UPDATE accounts SET enrollment_verifier = ? WHERE id = ?`, verifier, identity.AccountID); err != nil {
		a.serverError(response, err)
		return
	}
	now := unixNow()
	if _, err := transaction.ExecContext(request.Context(), `UPDATE devices SET revoked_at = COALESCE(revoked_at, ?) WHERE account_id = ? AND id <> ?`, now, identity.AccountID, identity.DeviceID); err != nil {
		a.serverError(response, err)
		return
	}
	if _, err := transaction.ExecContext(request.Context(), `UPDATE token_families SET revoked_at = COALESCE(revoked_at, ?) WHERE account_id = ? AND device_id <> ?`, now, identity.AccountID, identity.DeviceID); err != nil {
		a.serverError(response, err)
		return
	}
	if _, err := transaction.ExecContext(request.Context(), `DELETE FROM vaults WHERE account_id = ? AND revision <> ?`, identity.AccountID, newRevision); err != nil {
		a.serverError(response, err)
		return
	}
	if err := transaction.Commit(); err != nil {
		a.serverError(response, err)
		return
	}
	response.Header().Set("ETag", revisionETag(newRevision))
	response.WriteHeader(http.StatusNoContent)
}
