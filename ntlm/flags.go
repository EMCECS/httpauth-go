// Copyright 2016 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntlm

// flags contains NTLM message flags.
type flags uint32

const (
	NegotiateUnicode             = flags(1) // Indicates that Unicode strings are supported
	NegotiateOEM                 = flags(2) // Indicates that OEM strings are supported
	RequestTarget                = flags(4)
	NegotiateNTLM                = flags(0x200)
	NegotiateDomainSupplied      = flags(0x1000)
	NegotiateWorkstationSupplied = flags(0x2000)
	NegotiateLocalCall           = flags(0x4000)
	NegotiateAlwaysSign          = flags(0x8000)
	TargetTypeDomain             = flags(0x00010000)
	TargetTypeServer             = flags(0x00020000)
	NegotiateNTLM2Key            = flags(0x00080000)
	NegotiateTargetInfo          = flags(0x00800000)
	NegotiateVersion             = flags(0x02000000)
	Negotiate128                 = flags(0x20000000)
	Negotiate56                  = flags(0x80000000)
)

func decodeFlags(data []byte) flags {
	_ = data[3]
	ret := uint32(data[3])<<24 | uint32(data[2])<<16 | uint32(data[1])<<8 | uint32(data[0])
	return flags(ret)
}
