package main

import (
	"crypto/rand"
	"log"
	"time"

	"github.com/o1egl/paseto"

	"github.com/aead/chacha20poly1305"
)

func newSymmetricKey() []byte {
	key := make([]byte, 32)

	_, err := rand.Read(key)
	if err != nil {
		log.Fatalf("failed to read random bytes: %s", err)
	}
	return key
}

func main() {
	symmetricKey := newSymmetricKey() // Must be 32 bytes
	if len(symmetricKey) != chacha20poly1305.KeySize {
		log.Fatalf("invalid key size: must be exactly %d characters", chacha20poly1305.KeySize)
	}
	now := time.Now()
	exp := now.Add(24 * time.Hour)
	nbt := now

	jsonToken := paseto.JSONToken{
		Audience:   "test",
		Issuer:     "test_service",
		Jti:        "123",
		Subject:    "test_subject",
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}
	// Add custom claim    to the token
	jsonToken.Set("data", "this is a signed message")
	footer := "some footer"

	v2 := paseto.NewV2()
	// Encrypt data
	token, err := v2.Encrypt(symmetricKey, jsonToken, footer)
	if err != nil {
		log.Fatalf("failed to encrypte: %v", err)
	}
	log.Println(token)
	// token = "v2.local.E42A2iMY9SaZVzt-WkCi45_aebky4vbSUJsfG45OcanamwXwieieMjSjUkgsyZzlbYt82miN1xD-X0zEIhLK_RhWUPLZc9nC0shmkkkHS5Exj2zTpdNWhrC5KJRyUrI0cupc5qrctuREFLAvdCgwZBjh1QSgBX74V631fzl1IErGBgnt2LV1aij5W3hw9cXv4gtm_jSwsfee9HZcCE0sgUgAvklJCDO__8v_fTY7i_Regp5ZPa7h0X0m3yf0n4OXY9PRplunUpD9uEsXJ_MTF5gSFR3qE29eCHbJtRt0FFl81x-GCsQ9H9701TzEjGehCC6Bhw.c29tZSBmb290ZXI"

	// Decrypt data
	var newJsonToken paseto.JSONToken
	var newFooter string
	err = v2.Decrypt(token, symmetricKey, &newJsonToken, &newFooter)
	if err != nil {
		log.Fatal(err)
	}
}
