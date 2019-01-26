package can

import (
	"encoding/binary"
)

// TODO: Swap this out for a library when one is written

// Constants taken from Linux kernel C headers

// ExtendedFrameFormatFlag EFF/SFF is set in the MSB
const ExtendedFrameFormatFlag uint32 = uint32(0x80000000)

// RemoteTransmissionRequestFlag remote transmission request
const RemoteTransmissionRequestFlag uint32 = uint32(0x40000000)

// ErrorFlag error message frame
const ErrorFlag uint32 = uint32(0x20000000)

// StandardFrameFormatMask is a mask for standard frame format (SFF)
const StandardFrameFormatMask uint32 = uint32(0x000007FF)

// ExtendedFrameFormatMask is a mask for extended frame format (EFF)
const ExtendedFrameFormatMask uint32 = uint32(0x1FFFFFFF)

// ErrorMask is a mask for omit EFF, RTR, ERR flags
const ErrorMask uint32 = uint32(0x1FFFFFFF)

// Frame is a representation of the Linux can_frame struct
type Frame struct {
	// 32 bit CAN_ID + EFF/RTR/ERR flags
	canID uint32

	canDLC uint8
	data   [8]uint8
}

// IsExtendedFrame checks if the EFF flag is set
func IsExtendedFrame(frame *Frame) {

}

// IsRtrFrame checks if the RTR flag is set
func IsRtrFrame(frame *Frame) {

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

// FrameToBuffer converts a Frame to a byte buffer
func FrameToBuffer(frame *Frame, buffer []byte) {
	binary.LittleEndian.PutUint32(buffer[0:4], frame.canID)
	buffer[4] = frame.canDLC

	copy(buffer[8:], frame.data[:])
}
