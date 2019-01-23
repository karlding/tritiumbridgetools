package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"log"
	"net"
)

// TritiumUDPPacket represents a UDP packet received from the Tritium
// CAN-Ethernet bridge
type TritiumUDPPacket struct {
	// Magic number
	versionIdentifier uint64
	busNumber         uint8

	clientIdentifier uint64

	// CAN arbitration ID
	canID uint32

	// Flags is a 8-bit field
	// (flagHeartbeat << 7) | (flagSettings << 6) | (flagRtr << 1) | (flagExtendedID << 0)
	flagHeartbeat  bool
	flagSettings   bool
	flagRtr        bool
	flagExtendedID bool

	// Length
	length uint8
	// Data
	data uint64
}

func byteArrayToTritiumMessage(array []byte, tritiumPacket *TritiumUDPPacket) {
	//
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
	//
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
	fmt.Println(array)
	busIdentifier := binary.BigEndian.Uint64(array[0:8])
	// Mask out the high bits that
	tritiumPacket.versionIdentifier = busIdentifier >> 4
	tritiumPacket.busNumber = uint8(busIdentifier & (0x0F))

	fmt.Printf("Bus Identifier: 0x%x\n", busIdentifier)
	fmt.Printf("Version Identifier: 0x%x\n", tritiumPacket.versionIdentifier)
	fmt.Printf("Bus Number: 0x%x\n", tritiumPacket.busNumber)

	// Mask out the
	tritiumPacket.clientIdentifier = binary.BigEndian.Uint64(array[8:16])
	fmt.Printf("Client Identifier: 0x%x\n", tritiumPacket.clientIdentifier)

	tritiumPacket.canID = binary.BigEndian.Uint32(array[16:20])
	fmt.Printf("CAN ID: 0x%x\n", tritiumPacket.canID)

	flags := array[20]
	tritiumPacket.flagHeartbeat = (flags>>7)&uint8(1) == 1
	tritiumPacket.flagSettings = (flags>>6)&uint8(1) == 1
	tritiumPacket.flagRtr = (flags>>1)&uint8(1) == 1
	tritiumPacket.flagExtendedID = (flags>>0)&uint8(1) == 1
	fmt.Printf("Flags: 0x%x\n", flags)
	fmt.Printf("Heartbeat: %t\n", tritiumPacket.flagHeartbeat)
	fmt.Printf("Settings: %t\n", tritiumPacket.flagSettings)
	fmt.Printf("RTR: %t\n", tritiumPacket.flagRtr)
	fmt.Printf("Extended: %t\n", tritiumPacket.flagExtendedID)

	tritiumPacket.length = uint8(array[21])
	fmt.Printf("Length: 0x%x\n", tritiumPacket.length)

	tritiumPacket.data = binary.BigEndian.Uint64(array[22:30])
	fmt.Printf("Data: 0x%x\n", tritiumPacket.data)
}

func tritiumPacketToCanFrame(tritiumPacket *TritiumUDPPacket, sendFrame []byte) {
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
	// TODO: Set Extended bit if needed
	binary.LittleEndian.PutUint32(sendFrame[0:4], tritiumPacket.canID)

	// Set DLC
	sendFrame[4] = tritiumPacket.length

	// Data
	binary.LittleEndian.PutUint64(sendFrame[8:], tritiumPacket.data)

	// return sendFrame
}

func main() {
	flag.Parse()
	fmt.Println("tail: ", flag.Args())

	// SocketCAN setup
	vcan0, err := net.InterfaceByName("vcan0")
	if err != nil {
		log.Fatal(err)
		return
	}
	fd, err := unix.Socket(unix.AF_CAN, unix.SOCK_RAW, unix.CAN_RAW)
	if err != nil {
		return
	}
	addr := &unix.SockaddrCAN{Ifindex: vcan0.Index}
	unix.Bind(fd, addr)

	enp0s25, err := net.InterfaceByName("enp0s25")
	if err != nil {
		log.Fatal(err)
		return
	}
	// The Group Address is 239.255.60.60
	group := net.IPv4(239, 255, 60, 60)

	// The Tritium CAN-Ethernet bridge always broadcasts on port 4876
	c, err := net.ListenPacket("udp4", "0.0.0.0:4876")
	if err != nil {
		// error handling
		return
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(enp0s25, &net.UDPAddr{IP: group}); err != nil {
		// error handling
		return
	}

	b := make([]byte, 30)
	for {
		// (64 + 8 + 8 + 32 + 56 + 8 + 56 + 8) bits = 30 bytes
		numBytes, _, _, err := p.ReadFrom(b)
		fmt.Printf("Received %d bytes\n", numBytes)
		if err != nil {
			// error handling
			continue
		}

		if numBytes != 30 {
			fmt.Println(b)
			panic("Failed")
		}

		tritiumPacket := new(TritiumUDPPacket)
		byteArrayToTritiumMessage(b, tritiumPacket)

		fmt.Printf("CAN Id: %d\n", tritiumPacket.canID)
		fmt.Printf("Bus Number: 0x%x\n", tritiumPacket.busNumber)
		fmt.Printf("Client Identifier: 0x%x\n", tritiumPacket.clientIdentifier)
		fmt.Printf("Heartbeat: %t\n", tritiumPacket.flagHeartbeat)
		fmt.Printf("Settings: %t\n", tritiumPacket.flagSettings)
		fmt.Printf("RTR: %t\n", tritiumPacket.flagRtr)
		fmt.Printf("Extended: %t\n", tritiumPacket.flagExtendedID)
		fmt.Printf("Length: 0x%x\n", tritiumPacket.length)
		fmt.Printf("Data: 0x%x\n", tritiumPacket.data)

		sendFrame := make([]byte, 16)
		tritiumPacketToCanFrame(tritiumPacket, sendFrame)
		fmt.Println(sendFrame)
		// Now forward onto SocketCAN interface
	}
}
