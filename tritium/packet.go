package tritium

import (
	"golang.org/x/sys/unix"

	"github.com/karlding/tritiumbridgetools/socketcan"

	"encoding/binary"
	"fmt"
)

// magicNumber is the magic number denoting the Tritium UDP packet protocol
// version
var magicNumber = uint64(0x5472697469756)

// Packet represents a UDP packet received from the Tritium
// CAN-Ethernet bridge
type Packet struct {
	// Magic number
	VersionIdentifier uint64
	BusNumber         uint8

	ClientIdentifier uint64

	// CAN arbitration ID
	CanID uint32

	// Flags is a 8-bit field
	// (FlagHeartbeat << 7) | (FlagSettings << 6) | (FlagRtr << 1) | (FlagExtendedID << 0)
	FlagHeartbeat  bool
	FlagSettings   bool
	FlagRtr        bool
	FlagExtendedID bool

	// Length
	Length uint8
	// Data
	Data uint64
}

func byteArrayToTritiumMessage(array []byte, tritiumPacket *Packet) {
	// Identifier:
	//  * The CAN ID is contained in the low 11 bits (29 in extended mode)
	//
	// Flags:
	//
	// +-------------+
	// | Heartbeat   |
	// +-------------+
	// | Settings    |
	// +-------------+
	// | RTR         |
	// +-------------+
	// | Extended ID |
	// +-------------+
	//
	//  * Heartbeat: Indicates that this datagram contains a message from
	//    the bridge itself, rather than a bridged CAN packet.
	//  * Settings: Indicates that this datagram contains a setting for the
	//    bridge itself
	//  * RTR: Indicates that the data contained in this datagram should be
	//    sent as an RTR packet on the physical CAN network.
	//  * Extended ID: Indicates that this packet should be sent with an
	//    extended CAN identifier.
	//
	// Length:
	//  * indicates the length of the packet data, in bytes (max 8)
	//
	// Data:
	//  * the data contained in the physical CAN packet
	//  * Extra bytes are padded with 0s to result in 8 bytes of data
	tritiumPacket.CanID = binary.BigEndian.Uint32(array[0:4])
	fmt.Printf("CAN ID: 0x%x\n", tritiumPacket.CanID)

	flags := array[4]
	tritiumPacket.FlagHeartbeat = (flags>>7)&uint8(1) == 1
	tritiumPacket.FlagSettings = (flags>>6)&uint8(1) == 1
	tritiumPacket.FlagRtr = (flags>>1)&uint8(1) == 1
	tritiumPacket.FlagExtendedID = (flags>>0)&uint8(1) == 1
	fmt.Printf("Flags: 0x%x\n", flags)
	fmt.Printf("Heartbeat: %t\n", tritiumPacket.FlagHeartbeat)
	fmt.Printf("Settings: %t\n", tritiumPacket.FlagSettings)
	fmt.Printf("RTR: %t\n", tritiumPacket.FlagRtr)
	fmt.Printf("Extended: %t\n", tritiumPacket.FlagExtendedID)

	tritiumPacket.Length = uint8(array[5])
	fmt.Printf("Length: 0x%x\n", tritiumPacket.Length)

	tritiumPacket.Data = binary.BigEndian.Uint64(array[6:14])
	fmt.Printf("Data: 0x%x\n", tritiumPacket.Data)
}

// ByteArrayTCPToTritiumMessage converts a byte array received from a TCP
// connection to a Packet
func ByteArrayTCPToTritiumMessage(array []byte, tritiumPacket *Packet) {
	// TCP Packet Layout
	//
	// +-----------------------------+
	// | CAN ID (32 bits)            | 0 - 3
	// +-----------------------------+
	// | Flags (8 bits)              | 4
	// +-----------------------------+
	// | Length (8 bits)             | 5
	// +-----------------------------+
	// | Data (64 bits)              | 6 - 13
	// +-----------------------------+
	for key, val := range array {
		fmt.Printf("array[%d]: 0x%x\n", key, val)
	}
	byteArrayToTritiumMessage(array, tritiumPacket)
}

// ByteArrayToTritiumMessage converts a raw byte array as received from a
// Tritium CAN-Ethernet bridge to a Packet
func ByteArrayToTritiumMessage(array []byte, tritiumPacket *Packet) {
	// UDP Packet layout:
	//
	// +-----------------------------+
	// | Padding (8 bits)            | 0
	// +-----------------------------+
	// | Bus Identifier (56 bits)    | 1 - 7
	// +-----------------------------+
	// | Padding (8 bits)            | 8
	// +-----------------------------+
	// | Client Identifier (56 bits) | 9 - 15
	// +-----------------------------+
	// | CAN ID (32 bits)            | 16 - 19
	// +-----------------------------+
	// | Flags (8 bits)              | 20
	// +-----------------------------+
	// | Length (8 bits)             | 21
	// +-----------------------------+
	// | Data (64 bits)              | 22 - 29
	// +-----------------------------+
	//
	// Bus Identifier:
	// 	* The first 52 bits contain the magic number 0x5472697469756
	// 	  (Tritium)
	// 	* The LSB 4 bits represent the bus number that the packet was
	// 	  transmitted on (and can be configured with the Tritium tool)
	//
	// +------------------------------+
	// | Version Identifier (52 bits) |
	// +------------------------------+
	// | Bus Number (4 bits)          |
	// +------------------------------+
	//
	// Client Identifier:
	//  * The CAN-Ethernet bridges use the MAC address of their Ethernet
	//    interface as their client id
	fmt.Println(array)
	for i, val := range array {
		fmt.Printf("array[%d]: 0x%x\n", i, val)
	}
	busIdentifier := binary.BigEndian.Uint64(array[0:8])
	// Mask out the high bits that
	tritiumPacket.VersionIdentifier = busIdentifier >> 4
	tritiumPacket.BusNumber = uint8(busIdentifier & (0x0F))

	if tritiumPacket.VersionIdentifier != magicNumber {
		fmt.Println("Tritium Packet did not contain magic number.")
		return
		panic("Tritium Packet did not contain magic number.")
	}
	fmt.Printf("Bus Identifier: 0x%x\n", busIdentifier)
	fmt.Printf("Version Identifier: 0x%x\n", tritiumPacket.VersionIdentifier)
	fmt.Printf("Bus Number: 0x%x\n", tritiumPacket.BusNumber)

	// Mask out the
	tritiumPacket.ClientIdentifier = binary.BigEndian.Uint64(array[8:16])
	fmt.Printf("Client Identifier: 0x%x\n", tritiumPacket.ClientIdentifier)

	byteArrayToTritiumMessage(array[16:], tritiumPacket)
}

// PacketToSocketCANFrame converts a Tritium Packet representation to a
// SocketCAN frame
func PacketToSocketCANFrame(tritiumPacket *Packet, sendFrame []byte) {
	// 4 + 1 + 1 + 1 + 1 + 8 = 16
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
	// sendFrame := make([]byte, 16)

	// Set Arbitration ID
	canID := tritiumPacket.CanID
	if tritiumPacket.FlagExtendedID {
		canID = tritiumPacket.CanID | unix.CAN_EFF_FLAG
	}

	frame := can.Frame{}
	frame.CanID = canID
	frame.CanDLC = tritiumPacket.Length
	binary.BigEndian.PutUint64(frame.Data[:], tritiumPacket.Data)

	can.FrameToBuffer(&frame, sendFrame)

	// return sendFrame
}

// SocketCANToTritiumPacket converts a SocketCAN message buffer to a Tritium Packet representation
func SocketCANToTritiumPacket(sendFrame []byte, tritiumPacket *Packet, versionIdentifier uint64, busNumber uint8, clientIdentifier uint64) {
	// TODO: Once a Userspace library exists for working with CANFrame, switch
	// to using that.

	// Convert to a can.Frame first
	canFrame := new(can.Frame)
	can.BufferToCANFrame(sendFrame, canFrame)

	// Set magic number
	tritiumPacket.VersionIdentifier = versionIdentifier
	tritiumPacket.BusNumber = busNumber
	tritiumPacket.ClientIdentifier = clientIdentifier

	// CAN arbitration ID
	// TODO: Mask this properly
	tritiumPacket.CanID = canFrame.CanID

	// If CAN_EFF_FLAG is set on ID, then set FlagExtendedID
	// TODO: Add support for RTR frames
	// TODO: Add support for extended frames

	// Length
	tritiumPacket.Length = canFrame.CanDLC

	// Data
	tritiumPacket.Data = binary.BigEndian.Uint64(canFrame.Data[0:8])
}

// PacketToNetworkByteArray converts a Tritium Packet representation to a raw Byte Array to be sent over
// the network
func PacketToNetworkByteArray(tritiumPacket *Packet, buff []byte) {
	// Packet Layout
	//
	// +-----------------------------+
	// | Padding (8 bits)            | 0
	// +-----------------------------+
	// | Bus Identifier (56 bits)    | 1 - 7
	// +-----------------------------+
	// | Padding (8 bits)            | 8
	// +-----------------------------+
	// | Client Identifier (56 bits) | 9 - 15
	// +-----------------------------+
	// | CAN ID (32 bits)            | 16 - 19
	// +-----------------------------+
	// | Flags (8 bits)              | 20
	// +-----------------------------+
	// | Length (8 bits)             | 21
	// +-----------------------------+
	// | Data (64 bits)              | 22 - 29
	// +-----------------------------+
	binary.BigEndian.PutUint64(buff[0:8], (uint64(tritiumPacket.BusNumber))|(tritiumPacket.VersionIdentifier<<4))

	binary.BigEndian.PutUint64(buff[8:16], tritiumPacket.ClientIdentifier)

	binary.BigEndian.PutUint32(buff[16:20], tritiumPacket.CanID)

	// (FlagHeartbeat << 7) | (FlagSettings << 6) | (FlagRtr << 1) | (FlagExtendedID << 0)
	flags := uint8(0)
	if tritiumPacket.FlagHeartbeat {
		flags |= (1 << 7)
	}
	if tritiumPacket.FlagSettings {
		flags |= (1 << 6)
	}
	if tritiumPacket.FlagRtr {
		flags |= (1 << 1)
	}
	if tritiumPacket.FlagExtendedID {
		flags |= (1 << 0)
	}
	buff[20] = flags

	buff[21] = tritiumPacket.Length

	binary.BigEndian.PutUint64(buff[22:], tritiumPacket.Data)
}
