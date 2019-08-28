// Copyright 2016 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntlm

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidMessage = errors.New("NTLM: invalid message")
)

// osVersion describes the host's operating system build version.
type osVersion struct {
	Major uint8
	Minor uint8
	Build uint16
}

// Empty returns true if there is no data in the OSVersion struct.
func (v *osVersion) Empty() bool {
	return v.Major == 0
}

// Set is a utility function to quickly set all members of this struct in one call.
func (v *osVersion) Set(major uint8, minor uint8, build uint16) {
	v.Major = major
	v.Minor = minor
	v.Build = build
}

func (v *osVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Build)
}

// Decode fills in the members of an osVersion by extracting the data from a network message.
func (v *osVersion) Decode(data []byte) error {
	if len(data) < 8 {
		return ErrInvalidMessage
	}
	if data[7] != 0xf {
		// Last byte of the 8 bytes used to encode an OS Version structure
		// appears to be a version marker.  Only a version of 0xF is
		// accepted by this library.
		//
		// Checking this value may not be required, depending on the
		// strictness requirements.
		return ErrInvalidMessage
	}

	v.Build = uint16(data[3])<<8 | uint16(data[2])
	v.Minor = data[1]
	v.Major = data[0]
	return nil
}
