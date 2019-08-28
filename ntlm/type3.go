// Copyright 2016 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntlm

import (
	"bytes"
	"unicode/utf16"
)

type type3Message struct {
	LMResponse      []byte
	NTLMResponse    []byte
	TargetName      []byte
	UserName        []byte
	WorkstationName []byte
	SessionKey      []byte
	Flags           flags
	OSVersion       osVersion
}

func checkNTLMMessageSignature(data []byte) bool {
	return bytes.HasPrefix(data, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
}

func getNTLMMessageType(data []byte) uint32 {
	if len(data) < 12 {
		return 0
	}
	_ = data[11]
	return uint32(data[11]) | uint32(data[10])<<8 | uint32(data[9])<<16 | uint32(data[8])<<24
}

func readUint16(in []byte) uint16 {
	_ = in[1]
	ret := uint16(in[1])<<8 | uint16(in[0])
	return ret
}

func readUint32(in []byte) uint32 {
	_ = in[3]
	ret := uint32(in[3])<<24 | uint32(in[2])<<16 | uint32(in[1])<<8 | uint32(in[0])
	return ret
}

func ConvertString(f flags, data []byte) string {
	if f&NegotiateUnicode == 0 {
		panic("OEM charset not supported")
	}

	// TODO:  Handle incorrect utf16 data
	runes := make([]uint16, len(data)/2)
	for i := 0; i < len(data); i = i + 2 {
		runes[i/2] = uint16(data[i]) + uint16(data[i+1])<<8
	}

	return string(utf16.Decode(runes))
}

func (m *type3Message) Decode(in []byte) error {
	if len(in) < 52 {
		return ErrInvalidMessage
	}

	if !bytes.HasPrefix(in, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}) {
		return ErrInvalidMessage
	}

	if getNTLMMessageType(in) != 0x3000000 {
		return ErrInvalidMessage
	}

	minoffset := uint32(0)
	if true {
		length := readUint16(in[12:])
		_ /*allocated*/ = readUint16(in[14:])
		offset := readUint32(in[16:])
		if offset > minoffset {
			minoffset = offset
		}
		m.LMResponse = in[offset : offset+uint32(length)]
	}
	if true {
		length := readUint16(in[20:])
		_ /*allocated*/ = readUint16(in[22:])
		offset := readUint32(in[24:])
		if offset > minoffset {
			minoffset = offset
		}
		m.NTLMResponse = in[offset : offset+uint32(length)]
	}
	if true {
		length := readUint16(in[28:])
		_ /*allocated*/ = readUint16(in[30:])
		offset := readUint32(in[32:])
		if offset > minoffset {
			minoffset = offset
		}
		m.TargetName = in[offset : offset+uint32(length)]
	}
	if true {
		length := readUint16(in[36:])
		_ /*allocated*/ = readUint16(in[38:])
		offset := readUint32(in[40:])
		if offset > minoffset {
			minoffset = offset
		}
		m.UserName = in[offset : offset+uint32(length)]
	}
	if true {
		length := readUint16(in[44:])
		_ /*allocated*/ = readUint16(in[46:])
		offset := readUint32(in[48:])
		if offset > minoffset {
			minoffset = offset
		}
		m.WorkstationName = in[offset : offset+uint32(length)]
	}
	if minoffset >= 60 && len(in) >= 60 {
		length := readUint16(in[52:])
		_ /*allocated*/ = readUint16(in[54:])
		offset := readUint32(in[56:])
		if offset > minoffset {
			minoffset = offset
		}
		m.SessionKey = in[offset : offset+uint32(length)]
	}
	if minoffset >= 64 && len(in) >= 64 {
		m.Flags = decodeFlags(in[60:64])
	}
	if minoffset >= 72 && len(in) >= 72 {
		// There is data remaining.  Likely OS info
		m.OSVersion.Major = in[64]
		m.OSVersion.Minor = in[65]
		m.OSVersion.Build = uint16(in[67])<<8 | uint16(in[66])
	}

	return nil
}
