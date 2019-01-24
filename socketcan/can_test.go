package can

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBufferToCANFrame(t *testing.T) {
	canFrame := new(Frame)
	rawBuffer := []byte{1, 4, 0, 0, 6, 0, 0, 0, 6, 0, 53, 154, 238, 89, 0, 0}

	BufferToCANFrame(rawBuffer, canFrame)

	assert.Equal(t, uint32(0x401), canFrame.canID, "CAN frame ID was not equal")
	assert.Equal(t, uint8(6), canFrame.canDLC, "CAN frame length was not equal")
}
