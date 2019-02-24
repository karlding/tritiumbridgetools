package tritium

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestByteArrayTCPToTritiumMessage(t *testing.T) {
	// Test using
	canPacket := new(Packet)
	rawBuffer := []byte{
		0x00, 0x00, 0x04, 0x01, 0x00, 0x06, 0x11, 0x00,
		0x54, 0x0d, 0xbb, 0x19, 0x00, 0x00,
	}

	ByteArrayTCPToTritiumMessage(rawBuffer, canPacket)

	assert.Equal(t, false, canPacket.FlagHeartbeat, "FlagHeartbeat was not equal")
	assert.Equal(t, false, canPacket.FlagSettings, "FlagSettings was not equal")
	assert.Equal(t, false, canPacket.FlagRtr, "FlagRtr was not equal")
	assert.Equal(t, false, canPacket.FlagExtendedID, "FlagExtendedID was not equal")

	assert.Equal(t, uint32(0x401), canPacket.CanID, "CAN frame ID was not equal")
	assert.Equal(t, uint8(6), canPacket.Length, "CAN frame length was not equal")

	assert.Equal(t, uint64(0x1100540dbb190000), canPacket.Data, "Data is not equal")
}

func TestByteArrayTCPToTritiumMessageExtended(t *testing.T) {
	// Taken from ELCON UHF Charger Status Message
	canPacket := new(Packet)
	rawBuffer := []byte{
		0x18, 0xff, 0x50, 0xe5, 0x01, 0x08, 0x64, 0x00,
		0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	ByteArrayTCPToTritiumMessage(rawBuffer, canPacket)

	assert.Equal(t, false, canPacket.FlagHeartbeat, "FlagHeartbeat was not equal")
	assert.Equal(t, false, canPacket.FlagSettings, "FlagSettings was not equal")
	assert.Equal(t, false, canPacket.FlagRtr, "FlagRtr was not equal")
	assert.Equal(t, true, canPacket.FlagExtendedID, "FlagExtendedID was not equal")

	assert.Equal(t, uint32(0x18ff50e5), canPacket.CanID, "CAN frame ID was not equal")
	assert.Equal(t, uint8(8), canPacket.Length, "CAN frame length was not equal")

	assert.Equal(t, uint64(0x6400640000000000), canPacket.Data, "Data is not equal")
}

func TestByteArrayToTritiumMessageHeartbeat(t *testing.T) {
	// UDP test using Heartbeat packet
	canPacket := new(Packet)
	rxBuffer := []byte{
		0x00, 0x54, 0x72, 0x69, 0x74, 0x69, 0x75, 0x6d,
		0x00, 0x00, 0xfc, 0xc0, 0xcf, 0xc2, 0x50, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x80, 0x08, 0x01, 0xf4,
		0xfc, 0xc0, 0xcf, 0xc2, 0x50, 0x00,
	}

	ByteArrayToTritiumMessage(rxBuffer, canPacket)

	assert.Equal(t, uint64(0x5472697469756), canPacket.VersionIdentifier, "VersionIdentifier was not equal")
	assert.Equal(t, uint8(0xd), canPacket.BusNumber, "BusNumber was not equal")

	assert.Equal(t, uint64(0xfcc0cfc25000), canPacket.ClientIdentifier, "ClientIdentifier was not equal")

	assert.Equal(t, true, canPacket.FlagHeartbeat, "FlagHeartbeat was not equal")
	assert.Equal(t, false, canPacket.FlagSettings, "FlagSettings was not equal")
	assert.Equal(t, false, canPacket.FlagRtr, "FlagRtr was not equal")
	assert.Equal(t, false, canPacket.FlagExtendedID, "FlagExtendedID was not equal")
}

func TestPacketToNetworkByteArrayStandardMsg(t *testing.T) {
	// Taken from MS XII BMS Battery Voltage/Temperature Message
	canPacket := Packet{
		VersionIdentifier: uint64(0x5472697469756),
		BusNumber:         0xd,
		ClientIdentifier:  uint64(0xf8000c0a),
		CanID:             uint32(0x401),
		FlagExtendedID:    false,
		Length:            6,
		Data:              uint64(0x0a0066980b00), // TODO: Change this to an array?
	}
	networkBuffer := make([]byte, 30)
	expectedBuffer := []byte{
		0x00, 0x54, 0x72, 0x69, 0x74, 0x69, 0x75, 0x6d,
		0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x0c, 0x0a,
		0x00, 0x00, 0x04, 0x01, 0x00, 0x06, 0x00, 0x00,
		0x0a, 0x00, 0x66, 0x98, 0x0b, 0x00,
	}

	PacketToNetworkByteArray(&canPacket, networkBuffer)

	assert.Equal(t, expectedBuffer, networkBuffer, "Buffer was not equal")
}

func TestPacketToNetworkByteArrayExtendedMsg(t *testing.T) {
	// Taken from ELCON UHF Charger Status Message
	canPacket := Packet{
		VersionIdentifier: uint64(0x5472697469756),
		BusNumber:         0xd,
		ClientIdentifier:  uint64(0xf8000c0a),
		CanID:             uint32(0x18ff50e5),
		FlagExtendedID:    true,
		Length:            8,
		Data:              uint64(0x6400640000000000), // TODO: Change this to an array?
	}
	networkBuffer := make([]byte, 30)
	expectedBuffer := []byte{
		0x00, 0x54, 0x72, 0x69, 0x74, 0x69, 0x75, 0x6d,
		0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x0c, 0x0a,
		0x18, 0xff, 0x50, 0xe5, 0x01, 0x08, 0x64, 0x00,
		0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	PacketToNetworkByteArray(&canPacket, networkBuffer)

	assert.Equal(t, expectedBuffer, networkBuffer, "Buffer was not equal")
}

func TestByteArrayIdentity(t *testing.T) {
	// Test that converting to a Tritium Message and back results in the same
	// byte array
}
