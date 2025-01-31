package pkcs7

import (
	"errors"
)

// Replaces all indefinite length encodings of BER object with definite ones.
// With typical cases this is enough to make the result DER-compatible.
func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: input ber is empty")
	}

	var out []byte
	out, _, err := ber2derImpl(out, ber)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Maximum supported count of length bytes in the definite form of the BER length
// sequence. This allows sequences with up to 2**31 - 1 bytes.
const maxLengthOctetCount = 4

// Maximum number of bytes in DER length encoding: 1 prefix and the following
// bytes with the length bits.
const maxDERLengthSpan = 1 + maxLengthOctetCount

// encodes the length in DER format
// If the length fits in 7 bits, the value is encoded directly.
//
// Otherwise, the number of bytes to encode the length is first determined.
// This number is likely to be 4 or less for a 32bit length. This number is
// added to 0x80. The length is encoded in big endian encoding follow after
//
// Examples:
//
//	length | byte 1 | bytes n
//	0      | 0x00   | -
//	120    | 0x78   | -
//	200    | 0x81   | 0xC8
//	500    | 0x82   | 0x01 0xF4
func encodeLength(out []byte, length int) []byte {
	if length >= 128 {
		lengthSpan := 1
		for i := length; i > 255; i >>= 8 {
			lengthSpan++
		}
		out = append(out, 0x80|byte(lengthSpan))
		for i := lengthSpan; i > 0; i-- {
			out = append(out, byte(length>>uint((i-1)*8)))
		}
	} else {
		out = append(out, byte(length))
	}
	return out
}

func ber2derImpl(
	out []byte, ber []byte,
) ([]byte, int, error) {
	if len(ber) == 0 {
		return nil, 0, errors.New("ber2der: empty BER object")
	}
	b := ber[0]
	offset := 1
	if offset >= len(ber) {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		tag = 0
		for ber[offset] >= 0x80 {
			tag = tag*128 + ber[offset] - 0x80
			offset++
			if offset > len(ber) {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
		// jvehent 20170227: this doesn't appear to be used anywhere...
		//tag = tag*128 + ber[offset] - 0x80
		offset++
		if offset > len(ber) {
			return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
		}
	}
	// Append the BER tag
	out = append(out, ber[0:offset]...)

	isConstructed := (b & 0x20) != 0

	// read length
	var length int
	l := ber[offset]
	offset++
	if offset > len(ber) {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	indefinite := false
	if l > 0x80 {
		numberOfBytes := int(l & 0x7F)
		if numberOfBytes > maxLengthOctetCount {
			return nil, 0, errors.New("ber2der: BER tag length too long")
		}
		if numberOfBytes == maxLengthOctetCount && int(ber[offset]) > 0x7F {
			return nil, 0, errors.New("ber2der: BER tag length is negative")
		}
		if int(ber[offset]) == 0x0 {
			return nil, 0, errors.New("ber2der: BER tag length has leading zero")
		}
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + int(ber[offset])
			offset++
			if offset > len(ber) {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
		if length < 0 {
			return nil, 0, errors.New("ber2der: invalid negative value found in BER tag length")
		}
	} else if l == 0x80 {
		// Keep length at 0
		indefinite = true
	} else {
		length = (int)(l)
	}

	var contentEnd int
	if !indefinite {
		contentEnd = offset + length
		if contentEnd > len(ber) {
			return nil, 0, errors.New("ber2der: BER tag length is more than available data")
		}
	}

	if !isConstructed {
		if indefinite {
			return nil, 0, errors.New("ber2der: Indefinite form tag must have constructed encoding")
		}
		out = encodeLength(out, length)
		out = append(out, ber[offset:contentEnd]...)
		return out, contentEnd, nil
	}

	// Reserve the max length span in the buffer and encode the child elements.
	var reserved [maxDERLengthSpan]byte
	lengthWriteOffset := len(out)
	out = append(out, reserved[:]...)

	for indefinite || (offset != contentEnd) {
		var err error
		var n int
		out, n, err = ber2derImpl(out, ber[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += n
		if indefinite {
			if len(ber)-2 < offset {
				return nil, 0, errors.New("ber2der: Invalid BER format")
			}
			terminated := ber[offset] == 0 && ber[offset+1] == 0
			if terminated {
				offset += 2
				break
			}
		} else if offset > contentEnd {
			return nil, 0, errors.New(
				"ber2der: a nested object spans beyond parent's length")
		}
	}

	// Calculate the real length of children, encode that in the reserved space,
	// then move the children to the remove the hole between the actual and the
	// reserved spans.
	writtenLength := len(out) - maxDERLengthSpan - lengthWriteOffset
	outLength := encodeLength(
		out[lengthWriteOffset:lengthWriteOffset], writtenLength)
	encodedLengthSpan := len(outLength)
	copy(out[lengthWriteOffset+encodedLengthSpan:],
		out[lengthWriteOffset+maxDERLengthSpan:])
	out = out[:len(out)-maxDERLengthSpan+encodedLengthSpan]

	return out, offset, nil
}
