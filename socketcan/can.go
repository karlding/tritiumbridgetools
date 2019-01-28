package can

import (
	"golang.org/x/sys/unix"

	"encoding/binary"
)

// TODO: Swap this out for a library when one is written

// Frame is a representation of the Linux can_frame struct
type Frame struct {
	// 32 bit CAN_ID + EFF/RTR/ERR flags
	CanID uint32

	CanDLC uint8
	Data   [8]byte
}

// IsExtendedFrame checks if the EFF flag is set
func IsExtendedFrame(frame *Frame) bool {
	return (frame.CanID & unix.CAN_EFF_FLAG) == unix.CAN_EFF_FLAG
}

// IsRtrFrame checks if the RTR flag is set
func IsRtrFrame(frame *Frame) bool {
	return (frame.CanID & unix.CAN_RTR_FLAG) == unix.CAN_RTR_FLAG
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
	frame.CanID = canID

	canDLC := uint8(buffer[4])
	frame.CanDLC = canDLC

	copy(frame.Data[:], buffer[8:16])
}

// FrameToBuffer converts a Frame to a byte buffer
func FrameToBuffer(frame *Frame, buffer []byte) {
	binary.LittleEndian.PutUint32(buffer[0:4], frame.CanID)
	buffer[4] = frame.CanDLC

	copy(buffer[8:], frame.Data[:])
}
