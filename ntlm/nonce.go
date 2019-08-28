// Copyright 2016 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntlm

import (
	"crypto/rand"
)

const (
	// The length of a nonce
	nonceLen = 16
)

func createNonce(buffer []byte) error {
	for i := 0; i < len(buffer); {
		n, err := rand.Read(buffer[i:])
		if err != nil {
			return err
		}
		i += n
	}
	return nil
}
