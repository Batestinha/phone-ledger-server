package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testEnvironment struct {
	t      *testing.T
	store  *Store
	server *httptest.Server
}

type createdAccount struct {
	AccountID string        `json:"accountId"`
	Tokens    tokenResponse `json:"tokens"`
}

func newTestEnvironment(t *testing.T) *testEnvironment {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "server.db"), 3)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(NewHandler(store, slog.New(slog.NewTextHandler(io.Discard, nil))))
	environment := &testEnvironment{t: t, store: store, server: httpServer}
	t.Cleanup(func() {
		httpServer.Close()
		_ = store.Close()
	})
	return environment
}

func (e *testEnvironment) request(method, path string, body []byte, headers map[string]string) *http.Response {
	e.t.Helper()
	request, err := http.NewRequest(method, e.server.URL+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		e.t.Fatal(err)
	}
	return response
}

func (e *testEnvironment) jsonRequest(method, path string, value any) *http.Response {
	e.t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.request(method, path, body, map[string]string{"Content-Type": "application/json"})
}

func decodeResponse[T any](t *testing.T, response *http.Response) T {
	t.Helper()
	defer response.Body.Close()
	var value T
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func testDevice(t *testing.T, id, name string) (deviceRequest, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return deviceRequest{ID: id, Name: name, PublicKey: rawBase64.EncodeToString(publicKey)}, privateKey
}

func (e *testEnvironment) createAccount(accountID, deviceID string, enrollmentSecret []byte) (createdAccount, ed25519.PrivateKey) {
	e.t.Helper()
	invite, err := e.store.CreateInvite(context.Background(), 10*time.Minute, 1)
	if err != nil {
		e.t.Fatal(err)
	}
	device, privateKey := testDevice(e.t, deviceID, "First phone")
	verifier := sha256.Sum256(enrollmentSecret)
	response := e.jsonRequest(http.MethodPost, "/v1/accounts", accountRequest{
		InviteCode:         invite,
		AccountID:          accountID,
		EnrollmentVerifier: rawBase64.EncodeToString(verifier[:]),
		Device:             device,
	})
	if response.StatusCode != http.StatusCreated {
		e.t.Fatalf("create account status = %d, body=%s", response.StatusCode, readBody(response))
	}
	return decodeResponse[createdAccount](e.t, response), privateKey
}

func readBody(response *http.Response) string {
	defer response.Body.Close()
	value, _ := io.ReadAll(response.Body)
	return string(value)
}

func vaultHeaders(token string, revision int64, blob []byte) map[string]string {
	digest := sha256.Sum256(blob)
	return map[string]string{
		"Authorization":         "Bearer " + token,
		"Content-Type":          "application/octet-stream",
		"If-Match":              revisionETag(revision),
		"X-Phone-Ledger-Format": "1",
		"X-Content-SHA256":      rawBase64.EncodeToString(digest[:]),
	}
}

func TestAccountAuthenticationVaultConflictAndRollback(t *testing.T) {
	environment := newTestEnvironment(t)
	secret := bytes.Repeat([]byte{7}, 32)
	created, privateKey := environment.createAccount(strings.Repeat("a", 32), strings.Repeat("b", 32), secret)

	blob := bytes.Repeat([]byte("encrypted-vault-"), 3)
	response := environment.request(http.MethodPut, "/v1/vault", blob, vaultHeaders(created.Tokens.AccessToken, 0, blob))
	if response.StatusCode != http.StatusNoContent || response.Header.Get("ETag") != `"1"` {
		t.Fatalf("first upload status=%d etag=%s body=%s", response.StatusCode, response.Header.Get("ETag"), readBody(response))
	}
	response.Body.Close()

	response = environment.request(http.MethodGet, "/v1/vault", nil, map[string]string{"Authorization": "Bearer " + created.Tokens.AccessToken})
	got, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Equal(got, blob) || response.Header.Get("ETag") != `"1"` {
		t.Fatalf("download status=%d etag=%s blob=%q", response.StatusCode, response.Header.Get("ETag"), got)
	}

	response = environment.request(http.MethodPut, "/v1/vault", blob, vaultHeaders(created.Tokens.AccessToken, 0, blob))
	if response.StatusCode != http.StatusConflict || response.Header.Get("ETag") != `"1"` {
		t.Fatalf("stale upload status=%d etag=%s", response.StatusCode, response.Header.Get("ETag"))
	}
	response.Body.Close()

	if _, err := environment.store.db.Exec(`DELETE FROM vaults WHERE account_id = ?`, created.AccountID); err != nil {
		t.Fatal(err)
	}
	response = environment.request(http.MethodPut, "/v1/vault", blob, vaultHeaders(created.Tokens.AccessToken, 1, blob))
	if response.StatusCode != http.StatusNoContent || response.Header.Get("ETag") != `"2"` || response.Header.Get("X-Phone-Ledger-Rollback-Recovery") != "true" {
		t.Fatalf("rollback upload status=%d headers=%v", response.StatusCode, response.Header)
	}
	response.Body.Close()

	challengeHTTP := environment.jsonRequest(http.MethodPost, "/v1/auth/challenges", challengeRequest{AccountID: created.AccountID, DeviceID: strings.Repeat("b", 32)})
	if challengeHTTP.StatusCode != http.StatusCreated {
		t.Fatalf("challenge status=%d body=%s", challengeHTTP.StatusCode, readBody(challengeHTTP))
	}
	challenge := decodeResponse[challengeResponse](t, challengeHTTP)
	nonce, _ := rawBase64.DecodeString(challenge.Nonce)
	signature := ed25519.Sign(privateKey, authMessage(environment.store.InstanceID(), created.AccountID, strings.Repeat("b", 32), challenge.ChallengeID, nonce))
	exchange := exchangeRequest{ChallengeID: challenge.ChallengeID, Signature: rawBase64.EncodeToString(signature)}
	response = environment.jsonRequest(http.MethodPost, "/v1/auth/tokens", exchange)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", response.StatusCode, readBody(response))
	}
	challengeTokens := decodeResponse[tokenResponse](t, response)
	response = environment.jsonRequest(http.MethodPost, "/v1/auth/tokens", exchange)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("challenge replay status=%d", response.StatusCode)
	}
	response.Body.Close()

	response = environment.jsonRequest(http.MethodPost, "/v1/auth/refresh", refreshRequest{RefreshToken: challengeTokens.RefreshToken})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", response.StatusCode, readBody(response))
	}
	rotated := decodeResponse[tokenResponse](t, response)
	response = environment.jsonRequest(http.MethodPost, "/v1/auth/refresh", refreshRequest{RefreshToken: challengeTokens.RefreshToken})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("refresh reuse status=%d", response.StatusCode)
	}
	response.Body.Close()
	response = environment.request(http.MethodGet, "/v1/vault", nil, map[string]string{"Authorization": "Bearer " + rotated.AccessToken})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused family access status=%d", response.StatusCode)
	}
	response.Body.Close()
}

func TestRecoveryRotationRevokesOtherDevices(t *testing.T) {
	environment := newTestEnvironment(t)
	oldSecret := bytes.Repeat([]byte{3}, 32)
	created, _ := environment.createAccount(strings.Repeat("1", 32), strings.Repeat("2", 32), oldSecret)

	second, _ := testDevice(t, strings.Repeat("3", 32), "Second phone")
	response := environment.jsonRequest(http.MethodPost, "/v1/devices/enroll", enrollRequest{
		AccountID:        created.AccountID,
		EnrollmentSecret: rawBase64.EncodeToString(oldSecret),
		Device:           second,
	})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", response.StatusCode, readBody(response))
	}
	secondTokens := decodeResponse[tokenResponse](t, response)

	blob := bytes.Repeat([]byte("rotated-encrypted-vault"), 2)
	newSecret := bytes.Repeat([]byte{9}, 32)
	newVerifier := sha256.Sum256(newSecret)
	headers := vaultHeaders(created.Tokens.AccessToken, 0, blob)
	headers["X-Phone-Ledger-Enrollment-Verifier"] = rawBase64.EncodeToString(newVerifier[:])
	response = environment.request(http.MethodPut, "/v1/recovery", blob, headers)
	if response.StatusCode != http.StatusNoContent || response.Header.Get("ETag") != `"1"` {
		t.Fatalf("rotation status=%d body=%s", response.StatusCode, readBody(response))
	}
	response.Body.Close()
	var retained int
	if err := environment.store.db.QueryRow(`SELECT COUNT(*) FROM vaults WHERE account_id = ?`, created.AccountID).Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("rotation retained %d vault revisions, err=%v", retained, err)
	}

	response = environment.request(http.MethodGet, "/v1/devices", nil, map[string]string{"Authorization": "Bearer " + secondTokens.AccessToken})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked device status=%d", response.StatusCode)
	}
	response.Body.Close()

	third, _ := testDevice(t, strings.Repeat("4", 32), "Recovered phone")
	response = environment.jsonRequest(http.MethodPost, "/v1/devices/enroll", enrollRequest{AccountID: created.AccountID, EnrollmentSecret: rawBase64.EncodeToString(oldSecret), Device: third})
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old recovery secret status=%d", response.StatusCode)
	}
	response.Body.Close()
	response = environment.jsonRequest(http.MethodPost, "/v1/devices/enroll", enrollRequest{AccountID: created.AccountID, EnrollmentSecret: rawBase64.EncodeToString(newSecret), Device: third})
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("new recovery secret status=%d body=%s", response.StatusCode, readBody(response))
	}
	response.Body.Close()
}

func TestOnlineBackupPreservesInstanceAndInvites(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenStore(filepath.Join(directory, "source.db"), DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	originalID := store.InstanceID()
	if _, err := store.CreateInvite(context.Background(), time.Hour, 1); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(directory, "backup.db")
	if err := store.Backup(backupPath); err != nil {
		t.Fatal(err)
	}
	if err := store.Backup(backupPath); err == nil {
		t.Fatal("backup unexpectedly overwrote an existing destination")
	}
	_ = store.Close()
	restored, err := OpenStore(backupPath, DefaultRetention)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if restored.InstanceID() != originalID {
		t.Fatalf("instance id changed: %s != %s", restored.InstanceID(), originalID)
	}
	var invites int
	if err := restored.db.QueryRow(`SELECT COUNT(*) FROM invites`).Scan(&invites); err != nil || invites != 1 {
		t.Fatalf("backup invite count=%d err=%v", invites, err)
	}
}

func TestAuthenticationMessageMatchesAndroidVector(t *testing.T) {
	message := authMessage("inst", strings.Repeat("a", 32), strings.Repeat("b", 32), "challenge", []byte{0, 1, 2, 3})
	const expected = "AAAAFHBob25lLWxlZGdlci1hdXRoLXYxAAAABGluc3QAAAAgYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEAAAAgYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIAAAAJY2hhbGxlbmdlAAAABAABAgM"
	if actual := base64.RawURLEncoding.EncodeToString(message); actual != expected {
		t.Fatalf("authentication vector = %s", actual)
	}
}
