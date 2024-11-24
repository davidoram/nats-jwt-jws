package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// parseCredsFile extracts the JWT, private & public keys from a NATS credentials file.
func parseCredsFile(credsFilePath string) (string, nkeys.KeyPair, string, error) {
	contents, err := os.ReadFile(credsFilePath)
	if err != nil {
		return "", nil, "", fmt.Errorf("nats: %w", err)
	}
	userJWT, err := nkeys.ParseDecoratedJWT(contents)
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to parse JWT: %v", err)
	}
	privateKey, err := nkeys.ParseDecoratedNKey(contents)
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to parse seed: %v", err)
	}
	fmt.Printf("Private Key: %s\n", privateKey)

	claims, err := jwt.DecodeGeneric(userJWT)
	if err != nil {
		return "", nil, "", fmt.Errorf("failed to decode claims: %v", err)
	}
	publicKey := claims.Subject
	fmt.Printf("Public Key: %s\n", publicKey)

	return userJWT, privateKey, publicKey, nil
}

// createJWS simulates creating a JWS from a JWT signed with the user's private key.
func createJWS(userJWT string, privateKey nkeys.KeyPair) (string, error) {
	// userKey, err := nkeys.FromSeed([]byte(userSeed))
	// if err != nil {
	// 	return "", fmt.Errorf("failed to create nkey from seed: %v", err)
	// }

	// Sign the JWT with the provate key
	sig, err := privateKey.Sign([]byte(userJWT))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %v", err)
	}

	//base64 url encode the signature
	sigStr := base64.RawURLEncoding.EncodeToString(sig)
	jwsBytes := userJWT + "." + sigStr

	return string(jwsBytes), nil
}

// verifyJWS simulates a server verifying the JWS using the user's public key.
func verifyJWS(jwsStr, publicKey string) ([]byte, error) {
	// JWS is in the format <header>.<payload>.<signature>
	components := strings.Split(jwsStr, ".")
	if len(components) != 4 {
		return []byte{}, fmt.Errorf("invalid JWS format")
	}
	jws := []byte(components[0] + "." + components[1] + "." + components[2])
	_, err := jwt.Decode(string(jws))
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decode JWS: %v", err)
	}

	// Turn sig back into bytes from base64 URL encoding
	signature, err := base64.RawURLEncoding.DecodeString(components[3])
	if err != nil {
		return []byte{}, fmt.Errorf("failed to decode signature: %v", err)
	}

	userPubKey, err := nkeys.FromPublicKey(publicKey)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create nkey from public key: %v", err)
	}

	if err := userPubKey.Verify(jws, signature); err != nil {
		return []byte{}, fmt.Errorf("failed to verify JWS signature: %v", err)
	}

	return jws, nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s <path_to_creds_file>", os.Args[0])
	}
	credsFilePath := os.Args[1]

	// Parse the credentials file
	userJWT, privateKey, publicKey, err := parseCredsFile(credsFilePath)
	if err != nil {
		log.Fatalf("Error parsing creds file: %v", err)
	}

	// Create a JWS
	jws, err := createJWS(userJWT, privateKey)
	if err != nil {
		log.Fatalf("Error creating JWS: %v", err)
	}
	fmt.Println("JWS created successfully:", jws)

	decodedJWT, err := verifyJWS(jws, publicKey)
	if err != nil {
		log.Fatalf("Error verifying JWS: %v", err)
	}
	fmt.Println("JWT verified ok:", string(decodedJWT))
}
