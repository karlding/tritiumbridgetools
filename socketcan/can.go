package can

import (
	"encoding/binary"
)

// Frame is a representation of the Linux can_frame struct
type Frame struct {
	// 32 bit CAN_ID + EFF/RTR/ERR flags
	canID uint32

	canDLC uint8
	data   [8]uint8
}

// BufferToCANFrame converts a raw buffer (received over SocketCAN) to a
// CAN Frame representation
func BufferToCANFrame(buffer []byte, frame *Frame) {
	// Taken from the Linux kernel source:
	//   include/uapi/linux/can.h
	//
	// struct can_frame {
	//   canid_t can_id;  [> 32 bit CAN_ID + EFF/RTR/ERR flags <]
	//   __u8    can_dlc; [> frame payload length in byte (0 .. CAN_MAX_DLEN) <]
	//   __u8    __pad;   [> padding <]
	//   __u8    __res0;  [> reserved / padding <]
	//   __u8    __res1;  [> reserved / padding <]
	//   __u8    data[CAN_MAX_DLEN] __attribute__((aligned(8)));
	// };
	canID := binary.LittleEndian.Uint32(buffer[0:4])
	frame.canID = canID

	canDLC := uint8(buffer[4])
	frame.canDLC = canDLC

	copy(frame.data[:], buffer[8:16])
}
