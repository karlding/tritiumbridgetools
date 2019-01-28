package can

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBufferToCANFrameStandardBatteryVTMessage(t *testing.T) {
	// Test using the Battery Voltage/Temperature message from MS XII
	canFrame := new(Frame)
	rawBuffer := []byte{1, 4, 0, 0, 6, 0, 0, 0, 6, 0, 53, 154, 238, 89, 0, 0}

	BufferToCANFrame(rawBuffer, canFrame)

	assert.Equal(t, uint32(0x401), canFrame.CanID, "CAN frame ID was not equal")
	assert.Equal(t, uint8(6), canFrame.CanDLC, "CAN frame length was not equal")
	assert.Equal(t, canFrame.Data[0:8], rawBuffer[8:], "Data is not equal")
}

func TestBufferToCANFrameStandardDriveOutputMessage(t *testing.T) {
	// Test using the Drive Output message from MS XII
	canFrame := new(Frame)
	rawBuffer := []byte{72, 2, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 132, 0}

	BufferToCANFrame(rawBuffer, canFrame)

	assert.Equal(t, uint32(0x248), canFrame.CanID, "CAN frame ID was not equal")
	assert.Equal(t, uint8(8), canFrame.CanDLC, "CAN frame length was not equal")
	assert.Equal(t, canFrame.Data[0:8], rawBuffer[8:], "Data is not equal")
}

func TestBufferToCANFrameStandardPowerpathMessage(t *testing.T) {
	// Test using the Powerpath status message from MS XII
	canFrame := new(Frame)
	rawBuffer := []byte{3, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	BufferToCANFrame(rawBuffer, canFrame)

	assert.Equal(t, uint32(0x203), canFrame.CanID, "CAN frame ID was not equal")
	assert.Equal(t, uint8(4), canFrame.CanDLC, "CAN frame length was not equal")
	assert.Equal(t, canFrame.Data[0:8], rawBuffer[8:], "Data is not equal")
}

// TODO: Add a test for Extended IDs

func TestIdentityEncodeDecode(t *testing.T) {
	canFrame := new(Frame)
	rawBuffer := []byte{1, 4, 0, 0, 6, 0, 0, 0, 6, 0, 53, 154, 238, 89, 0, 0}

	BufferToCANFrame(rawBuffer, canFrame)

	// Now convert it back to a buffer
	buffer := make([]byte, 16)
	FrameToBuffer(canFrame, buffer)

	assert.Equal(t, rawBuffer, buffer, "Buffers were not equal")
}
