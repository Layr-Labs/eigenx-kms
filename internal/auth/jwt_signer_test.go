package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/require"
)

func generateTestPKCS1PEM(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func generateTestPKCS8PEM(t *testing.T, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}

func TestNewJWTSigner_PKCS1(t *testing.T) {
	pemStr := generateTestPKCS1PEM(t, 2048)
	signer, err := NewJWTSigner(pemStr, time.Hour)
	require.NoError(t, err)
	require.NotNil(t, signer)
}

func TestNewJWTSigner_PKCS8(t *testing.T) {
	pemStr := generateTestPKCS8PEM(t, 2048)
	signer, err := NewJWTSigner(pemStr, time.Hour)
	require.NoError(t, err)
	require.NotNil(t, signer)
}

func TestNewJWTSigner_InvalidPEM(t *testing.T) {
	_, err := NewJWTSigner("not-a-pem", time.Hour)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no PEM block found")
}

func TestSignAttestationJWT_Claims(t *testing.T) {
	pemStr := generateTestPKCS1PEM(t, 2048)
	expiration := 24 * time.Hour
	signer, err := NewJWTSigner(pemStr, expiration)
	require.NoError(t, err)

	appID := "0x1234567890abcdef1234567890abcdef12345678"
	imageDigest := "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	tokenStr, err := signer.SignAttestationJWT(appID, imageDigest)
	require.NoError(t, err)
	require.NotEmpty(t, tokenStr)

	// Verify the JWT with the public key
	pubKey := signer.PublicKey()
	parsed, err := jwt.Parse([]byte(tokenStr), jwt.WithKey(jwa.RS256(), pubKey))
	require.NoError(t, err)

	// Check standard claims
	iss, ok := parsed.Issuer()
	require.True(t, ok)
	require.Equal(t, jwtIssuer, iss)

	sub, ok := parsed.Subject()
	require.True(t, ok)
	require.Equal(t, appID, sub)

	iat, ok := parsed.IssuedAt()
	require.True(t, ok)
	require.WithinDuration(t, time.Now(), iat, 5*time.Second)

	exp, ok := parsed.Expiration()
	require.True(t, ok)
	require.WithinDuration(t, time.Now().Add(expiration), exp, 5*time.Second)

	// Check custom claims
	var gotAppID string
	require.NoError(t, parsed.Get("appId", &gotAppID))
	require.Equal(t, appID, gotAppID)

	var gotDigest string
	require.NoError(t, parsed.Get("imageDigest", &gotDigest))
	require.Equal(t, imageDigest, gotDigest)
}

func TestSignAttestationJWT_VerifiableWithPublicKey(t *testing.T) {
	pemStr := generateTestPKCS1PEM(t, 2048)
	signer, err := NewJWTSigner(pemStr, time.Hour)
	require.NoError(t, err)

	tokenStr, err := signer.SignAttestationJWT("app1", "sha256:abc123")
	require.NoError(t, err)

	// Verification should succeed with the correct public key
	_, err = jwt.Parse([]byte(tokenStr), jwt.WithKey(jwa.RS256(), signer.PublicKey()))
	require.NoError(t, err)

	// Verification should fail with a different key
	otherPEM := generateTestPKCS1PEM(t, 2048)
	otherSigner, err := NewJWTSigner(otherPEM, time.Hour)
	require.NoError(t, err)
	_, err = jwt.Parse([]byte(tokenStr), jwt.WithKey(jwa.RS256(), otherSigner.PublicKey()))
	require.Error(t, err)
}
