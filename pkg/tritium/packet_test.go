package tritium

import (
	"testing"

	// "encoding/binary"

	"github.com/stretchr/testify/assert"
)

func TestByteArrayTCPToTritiumMessage(t *testing.T) {
	// Test using
	canPacket := new(Packet)
	rawBuffer := []byte{0, 0, 4, 1, 0, 6, 17, 0, 84, 13, 187, 25, 0, 0}

	// paddedData := []byte{0, 0, 0, 0, 25, 187, 13, 84}

	// 2019/02/03 17:26:45 kral is doing some testing [0 0 4 1 0 6 18 0 225 16 46 22 0 0]

	ByteArrayTCPToTritiumMessage(rawBuffer, canPacket)
	assert.Equal(t, uint32(0x401), canPacket.CanID, "CAN frame ID was not equal")
	assert.Equal(t, uint8(6), canPacket.Length, "CAN frame length was not equal")

	// data := binary.BigEndian.Uint64(paddedData[:])
	assert.Equal(t, uint64(0x1100540dbb190000), canPacket.Data, "Data is not equal")
	// assert.Equal(t, data, canPacket.Data, "Data is not equal")
}

// TODO: Add a test for Extended IDs as well

func TestByteArrayToTritiumMessage(t *testing.T) {
	// UDP
}

func TestByteArrayIdentity(t *testing.T) {
	// Test that converting to a Tritium Message and back results in the same
	// byte array
}
