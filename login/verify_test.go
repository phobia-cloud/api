// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package login_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"phobia.cloud/api/login"
)

const ( // valid login info
	challengeHidden = "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2"
	challengeVisual = "2015-03-23 17:39:22"
	publicKey       = "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45"
	signature       = "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02"
	version         = 2
)

func Verify_Valid(t *testing.T) {
	err := login.Verify(challengeHidden, challengeVisual, publicKey, signature, version)
	assert.NoError(t, err)
}

func TestVerify_UnsupportedVersion(t *testing.T) {
	for _, v := range []int{-1, 0, 3, 10} {
		err := login.Verify(challengeHidden, challengeVisual, publicKey, signature, v)
		assert.EqualError(t, err, fmt.Sprintf("unsupported version: %d", v))
	}
}

func TestVerify_WrongVersion(t *testing.T) {
	err := login.Verify(challengeHidden, challengeVisual, publicKey, signature, 1)
	assert.EqualError(t, err, login.ErrInvalidSignature.Error())
}

func TestVerify_InvalidChallengeHidden(t *testing.T) {
	for _, tt := range []struct {
		challengeHidden string
		expectedError   string
	}{
		{
			challengeHidden: "",
			expectedError:   login.ErrInvalidSignature.Error(),
		},
		{
			challengeHidden: "ad8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
			expectedError:   login.ErrInvalidSignature.Error(),
		},
		{
			challengeHidden: "Xd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c2",
			expectedError:   "failed to decode challenge hidden: encoding/hex: invalid byte: U+0058 'X'",
		},
		{
			challengeHidden: "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c",
			expectedError:   "failed to decode challenge hidden: encoding/hex: odd length hex string",
		},
		{
			challengeHidden: "cd8552569d6e4509266ef137584d1e62c7579b5b8ed69bbafa4b864c6521e7c200",
			expectedError:   login.ErrInvalidSignature.Error(),
		},
		{
			challengeHidden: "e89541ab65d371ebd3d3ea7eed0f00d8ef79b247efa537029843bff62b4a4243",
			expectedError:   login.ErrInvalidSignature.Error(),
		},
	} {
		err := login.Verify(tt.challengeHidden, challengeVisual, publicKey, signature, version)
		assert.EqualError(t, err, tt.expectedError, tt.challengeHidden)
	}
}

func TestVerify_InvalidChallengeVisual(t *testing.T) {
	for _, cv := range []string{
		"",
		"invalid",
		"2015-03-23",
		"2015-03-23 17:39:21",
	} {
		err := login.Verify(challengeHidden, cv, publicKey, signature, version)
		assert.EqualError(t, err, login.ErrInvalidSignature.Error(), cv)
	}
}

func TestVerify_InvalidPublicKey(t *testing.T) {
	for _, tt := range []struct {
		publicKey     string
		expectedError string
	}{
		{
			publicKey:     "",
			expectedError: "failed to parse public key: pubkey string is empty",
		},
		{
			publicKey:     "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f44",
			expectedError: "failed to parse public key: invalid square root",
		},
		{
			publicKey:     "a23a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
			expectedError: "failed to parse public key: invalid magic in compressed pubkey string: 162",
		},
		{
			publicKey:     "X23a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
			expectedError: "failed to decode public key: encoding/hex: invalid byte: U+0058 'X'",
		},
		{
			publicKey:     "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f4",
			expectedError: "failed to decode public key: encoding/hex: odd length hex string",
		},
		{
			publicKey:     "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f4500",
			expectedError: "failed to parse public key: invalid pub key length 34",
		},
		{
			publicKey:     "03da970504d5f1a37a5a93ffd7e11ee43bf8838d245360b331eae8397392a6addd",
			expectedError: login.ErrInvalidSignature.Error(),
		},
	} {
		err := login.Verify(challengeHidden, challengeVisual, tt.publicKey, signature, version)
		assert.EqualError(t, err, tt.expectedError, tt.publicKey)
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	for _, tt := range []struct {
		signature     string
		expectedError string
	}{
		{
			signature:     "",
			expectedError: login.ErrInvalidSignature.Error(),
		},
		{
			signature:     "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba01",
			expectedError: login.ErrInvalidSignature.Error(),
		},
		{
			signature:     "a0f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
			expectedError: login.ErrInvalidSignature.Error(),
		},
		{
			signature:     "X0f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba02",
			expectedError: "failed to decode signature: encoding/hex: invalid byte: U+0058 'X'",
		},
		{
			signature:     "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba0",
			expectedError: "failed to decode signature: encoding/hex: odd length hex string",
		},
		{
			signature:     "20f2d1a42d08c3a362be49275c3ffeeaa415fc040971985548b9f910812237bb41770bf2c8d488428799fbb7e52c11f1a3404011375e4080e077e0e42ab7a5ba0200",
			expectedError: login.ErrInvalidSignature.Error(),
		},
		{
			signature:     "1f34f4367c9f749f03e17e533faeac6c06fb86b09f9bbb8e64866b814d14ee2aa5090b0120ae5d37b421f2b84134ba0180e691b80decc8451e3cedde104d23ac12",
			expectedError: login.ErrInvalidSignature.Error(),
		},
	} {
		err := login.Verify(challengeHidden, challengeVisual, publicKey, tt.signature, version)
		assert.EqualError(t, err, tt.expectedError, tt.signature)
	}
}
