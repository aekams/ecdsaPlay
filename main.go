package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"playgroundgo/ecdsaplay"
)

func main() {
	// Positive Test Case
	fmt.Println("Positive Test Case")
	key, err := ecdsaplay.GeneratePrivatePublicKeyPair(elliptic.P256())
	if err != nil {
		panic(err)
	}

	publicKeyX, publicKeyY := key.PublicX, key.PublicY

	messageHash := sha256.Sum256([]byte("Take the red pill!"))
	signatureR, signatureS, err := ecdsaplay.Sign(key, messageHash[:])
	if err != nil {
		panic(err)
	}

	verification := ecdsaplay.Verify(signatureR, signatureS, publicKeyX, publicKeyY, key.Curve, messageHash[:])
	fmt.Println("Valid Signature: ", verification)

	// Negative Test Case
	fmt.Println("Negative Test Case (Invalid Message Hash)")
	newMessageHash := sha256.Sum256([]byte("Take the green pill!"))
	verification = ecdsaplay.Verify(signatureR, signatureS, key.PublicX, key.PublicY, key.Curve, newMessageHash[:])
	fmt.Println("Valid Signature: ", verification)

}
