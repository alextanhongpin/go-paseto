package main

import (
	"log"
	"time"

	"github.com/o1egl/paseto"
)

func main() {

	symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY") // Must be 32 bytes.
	now := time.Now()
	exp := now.Add(24 * time.Hour)
	nbf := now

	jsonToken := paseto.JSONToken{
		Audience:   "test",
		Issuer:     "test_service",
		Jti:        "123",
		Subject:    "test_subject",
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbf,
	}
	// Add custom claims to the token.
	jsonToken.Set("data", "this is a signed message")
	footer := "some footer"

	// Encrypt data.
	token, err := paseto.Encrypt(symmetricKey, jsonToken, footer)
	if err != nil {
		panic(err)
	}
	log.Println("token", token)

	var newJsonToken paseto.JSONToken
	var newFooter string
	if err := paseto.Decrypt(token, symmetricKey, &newJsonToken, &newFooter); err != nil {
		panic(err)
	}
	log.Println("newJsonToken", newJsonToken)
	log.Println("footer", footer)
}
