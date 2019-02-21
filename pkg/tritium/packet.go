package tritium

import (
	"encoding/binary"
	"log"
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

	flags := array[4]
	tritiumPacket.FlagHeartbeat = (flags>>7)&uint8(1) == 1
	tritiumPacket.FlagSettings = (flags>>6)&uint8(1) == 1
	tritiumPacket.FlagRtr = (flags>>1)&uint8(1) == 1
	tritiumPacket.FlagExtendedID = (flags>>0)&uint8(1) == 1

	tritiumPacket.Length = uint8(array[5])

	tritiumPacket.Data = binary.BigEndian.Uint64(array[6:14])
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
	busIdentifier := binary.BigEndian.Uint64(array[0:8])
	// Mask out the high bits that
	tritiumPacket.VersionIdentifier = busIdentifier >> 4
	tritiumPacket.BusNumber = uint8(busIdentifier & (0x0F))

	if tritiumPacket.VersionIdentifier != magicNumber {
		log.Println("Tritium Packet did not contain magic number.")
		return
		panic("Tritium Packet did not contain magic number.")
	}

	// Mask out the
	tritiumPacket.ClientIdentifier = binary.BigEndian.Uint64(array[8:16])

	byteArrayToTritiumMessage(array[16:], tritiumPacket)
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
