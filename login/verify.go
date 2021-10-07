// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package login

import (
	_sha256 "crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
)

var ErrInvalidSignature = errors.New("signature does not match public key or challenge")

// Verify verifies if signature is valid for the provided challenge and public
// key.
//
// challengeHidden is a randomly generated challenge by the ChallengeHidden
// function.
//
// challengeVisual is a representation of the current time created by the
// ChallengeVisual function. It is displayed to the user on the Trezor device.
//
// publicKey is the public key of the Trezor device dedicated for web login.
//
// signature is the signature created by the Trezor device when signing the
// challenge.
//
// version determines how the challenge is created from challengeHidden and
// challengeVisual. Valid versions are 1 and 2. If not sure, use version 2.
//
// The function expects that challengeHidden, publicKey, and signature are
// hex-encoded.
func Verify(challengeHidden, challengeVisual, publicKey, signature string, version int) error {
	challengeHiddenBytes, err := hex.DecodeString(challengeHidden)
	if err != nil {
		return fmt.Errorf("failed to decode challenge hidden: %v", err)
	}

	challengeVisualBytes := []byte(challengeVisual)

	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %v", err)
	}

	pubKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}

	var challenge []byte
	switch version {
	case 1:
		challenge = append(challengeHiddenBytes, challengeVisualBytes...)
	case 2:
		challenge = append(sha256(challengeHiddenBytes), sha256(challengeVisualBytes)...)
	default:
		return fmt.Errorf("unsupported version: %d", version)
	}

	magicBytes := []byte("Bitcoin Signed Message:\n")

	var msg []byte
	msg = append(msg, byte(len(magicBytes)))
	msg = append(msg, magicBytes...)
	msg = append(msg, byte(len(challenge)))
	msg = append(msg, challenge...)
	hash := sha256(sha256(msg))

	recoveredKey, _, err := btcec.RecoverCompact(btcec.S256(), signatureBytes, hash)
	if err != nil {
		return ErrInvalidSignature
	}

	if !recoveredKey.IsEqual(pubKey) {
		return ErrInvalidSignature
	}

	return nil
}

func sha256(msg []byte) []byte {
	hash := _sha256.Sum256(msg)
	return hash[:]
}
