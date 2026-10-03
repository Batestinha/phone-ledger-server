package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

var rawBase64 = base64.RawURLEncoding

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, fmt.Errorf("generate random value: %w", err)
	}
	return value, nil
}

func randomToken(size int) (string, error) {
	value, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return rawBase64.EncodeToString(value), nil
}

func tokenHash(value string) []byte {
	hash := sha256.Sum256([]byte(value))
	return hash[:]
}

func newUUID() (string, error) {
	value, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	hexValue := hex.EncodeToString(value)
	return strings.Join([]string{hexValue[0:8], hexValue[8:12], hexValue[12:16], hexValue[16:20], hexValue[20:32]}, "-"), nil
}

func validOpaqueID(value string) bool {
	if len(value) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}
