package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const jwtIssuer = "eigenx-kms"

type JWTSigner struct {
	privateKey *rsa.PrivateKey
	expiration time.Duration
}

func NewJWTSigner(privateKeyPEM string, expiration time.Duration) (*JWTSigner, error) {
	key, err := parseRSAPrivateKey([]byte(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	return &JWTSigner{
		privateKey: key,
		expiration: expiration,
	}, nil
}

func (s *JWTSigner) SignAttestationJWT(appID, imageDigest string) (string, error) {
	now := time.Now()

	token := jwt.New()
	if err := token.Set(jwt.IssuerKey, jwtIssuer); err != nil {
		return "", fmt.Errorf("failed to set issuer: %w", err)
	}
	if err := token.Set(jwt.SubjectKey, appID); err != nil {
		return "", fmt.Errorf("failed to set subject: %w", err)
	}
	if err := token.Set(jwt.IssuedAtKey, now); err != nil {
		return "", fmt.Errorf("failed to set issued at: %w", err)
	}
	if err := token.Set(jwt.ExpirationKey, now.Add(s.expiration)); err != nil {
		return "", fmt.Errorf("failed to set expiration: %w", err)
	}
	if err := token.Set("appId", appID); err != nil {
		return "", fmt.Errorf("failed to set appId: %w", err)
	}
	if err := token.Set("imageDigest", imageDigest); err != nil {
		return "", fmt.Errorf("failed to set imageDigest: %w", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), s.privateKey))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return string(signed), nil
}

// PublicKey returns the public key corresponding to the signing private key.
func (s *JWTSigner) PublicKey() *rsa.PublicKey {
	return &s.privateKey.PublicKey
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not an RSA private key")
		}
		return rsaKey, nil
	}

	// Fall back to PKCS1
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse as PKCS8 or PKCS1: %w", err)
	}
	return rsaKey, nil
}
