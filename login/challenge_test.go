// Copyright (C) 2021 Kaloyan Raev
// See LICENSE for copying information.

package login_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"phobia.cloud/api/login"
)

func TestChallengeHidden(t *testing.T) {
	challenge1 := login.ChallengeHidden()
	assert.Len(t, challenge1, 64)
	_, err := hex.DecodeString(challenge1)
	assert.NoError(t, err)

	challenge2 := login.ChallengeHidden()
	assert.Len(t, challenge2, 64)
	_, err = hex.DecodeString(challenge2)
	assert.NoError(t, err)

	assert.NotEqual(t, challenge1, challenge2)
}

func TestChallengeVisual(t *testing.T) {
	challenge := login.ChallengeVisual()
	asTime, err := time.ParseInLocation("2006-01-02 15:04:05", challenge, time.Local)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), asTime, time.Minute)
}
