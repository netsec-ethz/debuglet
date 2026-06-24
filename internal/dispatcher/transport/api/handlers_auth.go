package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/blake2b"
)

// personalMessageIntent is the Sui intent prefix for personal messages [app=3, version=0, scope=0].
var personalMessageIntent = []byte{3, 0, 0}

func validateSuiAddress(addr string) error {
	if len(addr) != 66 {
		return fmt.Errorf("address must be 66 characters (0x + 64 hex), got %d", len(addr))
	}
	if addr[:2] != "0x" {
		return fmt.Errorf("address must start with 0x")
	}
	for i, c := range addr[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("address contains invalid character %q at position %d", c, i+2)
		}
	}
	return nil
}

type VerifyRequest struct {
	Address   string `json:"address"`
	Signature string `json:"signature"` // base64 flag(1) || sig(64) || pubkey(32)
}

// GET /auth/nonce?address=0x...
// Issues a one-time challenge nonce for the given wallet address.
func (h *Handler) GetNonce(c echo.Context) error {
	address := strings.ToLower(c.QueryParam("address"))
	if address == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "missing address")
	}
	if err := validateSuiAddress(address); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid address: "+err.Error())
	}

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate nonce")
	}
	nonce := hex.EncodeToString(nonceBytes)

	if err := h.database.StoreChallenge(address, nonce, time.Minute); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to store challenge")
	}
	return c.JSON(http.StatusOK, map[string]string{"nonce": nonce})
}

// PUT /auth/verify
// Verifies a signed nonce and issues a session token on success.
func (h *Handler) Verify(c echo.Context) error {
	var req VerifyRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	address := strings.ToLower(req.Address)
	if err := validateSuiAddress(address); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid address: "+err.Error())
	}
	// Ed25519 signature: base64(97 bytes) = 132 chars. Allow headroom for other schemes.
	if len(req.Signature) == 0 || len(req.Signature) > 512 {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid signature length")
	}

	// Consume the challenge — single use, also validates expiry.
	nonce, err := h.database.GetAndDeleteChallenge(address)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "no valid challenge: "+err.Error())
	}

	// Reconstruct the BCS-encoded message the wallet signed: ULEB128(len) || UTF-8(nonce).
	// The frontend passes new TextEncoder().encode(nonce) to signPersonalMessage; the wallet
	// wraps it in BCS (vector<u8>) before signing and returning in the bytes field.
	msgBCS := bcsEncodeBytes([]byte(nonce))

	// Verify the Sui wallet signature.
	if err := verifySuiSignature(address, req.Signature, msgBCS); err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid signature: "+err.Error())
	}

	// Issue a 32-byte opaque session token, valid for 24 hours.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate session token")
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)
	if err := h.database.StoreSession(address, token, time.Hour); err != nil {
		h.logger.Info("err", zap.Error(err))
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to store session")
	}

	return c.JSON(http.StatusOK, map[string]string{"token": token, "address": address})
}

// verifySuiSignature verifies an Ed25519 Sui personal-message signature.
//
// sigB64 is base64(flag || sig[64] || pubkey[32]).
// msgBCS is the raw BCS bytes as returned by the wallet's signPersonalMessage
// (ULEB128 length prefix + UTF-8 message content). The wallet signs
// Blake2b-256(intent_prefix || msgBCS).
func verifySuiSignature(address, sigB64 string, msgBCS []byte) error {
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}
	if len(sigBytes) == 0 {
		return fmt.Errorf("empty signature")
	}

	flag := sigBytes[0]
	if flag != 0x00 {
		// Secp256k1 (0x01) and Secp256r1 (0x02) require different verification.
		return fmt.Errorf("unsupported key scheme (flag=0x%02x); only Ed25519 (0x00) is supported", flag)
	}
	// Ed25519: flag(1) + sig(64) + pubkey(32) = 97 bytes total.
	if len(sigBytes) != 97 {
		return fmt.Errorf("invalid signature length: got %d, want 97", len(sigBytes))
	}
	sig := sigBytes[1:65]
	pubkey := sigBytes[65:]

	// Signed digest = Blake2b-256(personal_message_intent || bcs_message).
	h, _ := blake2b.New256(nil)
	h.Write(personalMessageIntent)
	h.Write(msgBCS)
	digest := h.Sum(nil)

	if !ed25519.Verify(pubkey, digest, sig) {
		return fmt.Errorf("signature does not verify")
	}

	// Sui address = Blake2b-256(flag || pubkey), all 32 bytes as hex.
	h2, _ := blake2b.New256(nil)
	h2.Write([]byte{flag})
	h2.Write(pubkey)
	derived := fmt.Sprintf("0x%x", h2.Sum(nil))

	if !strings.EqualFold(derived, address) {
		return fmt.Errorf("address mismatch: derived %s, claimed %s", derived, address)
	}
	return nil
}

// bcsEncodeBytes BCS-encodes a byte slice as vector<u8>: ULEB128(length) || bytes.
// This matches what the Sui wallet's signPersonalMessage wraps the message in before signing.
func bcsEncodeBytes(b []byte) []byte {
	length := uint64(len(b))
	var prefix []byte
	for {
		byteVal := byte(length & 0x7f)
		length >>= 7
		if length > 0 {
			byteVal |= 0x80
		}
		prefix = append(prefix, byteVal)
		if length == 0 {
			break
		}
	}
	return append(prefix, b...)
}
