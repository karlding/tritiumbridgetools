package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/net/ipv4"
	"log"
	"net"
)

type TritiumUdpPacket struct {
	busIdentifier    uint64
	clientIdentifier uint64
	canId            uint32
	flags            uint8
	length           uint8
	data             uint64
}

func main() {
	flag.Parse()
	fmt.Println("tail: ", flag.Args())

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

	b := make([]byte, 1500)
	for {
		// (64 + 8 + 8 + 32 + 56 + 8 + 56 + 8) bits = 30 bytes
		numBytes, _, _, err := p.ReadFrom(b)
		if err != nil {
			// error handling
			continue
		}

		if numBytes != 30 {
			fmt.Printf("Received %d bytes\n", numBytes)
			fmt.Println(b)
			panic("Failed")
		}

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
		fmt.Printf("Received %d bytes\n", numBytes)
		fmt.Println(b)
		busIdentifier := binary.BigEndian.Uint64(b[0:8])
		// Mask out the high bits that
		versionIdentifier := busIdentifier >> 4
		busNumber := busIdentifier & (0x0F)

		fmt.Printf("Bus Identifier: 0x%x\n", busIdentifier)
		fmt.Printf("Version Identifier: 0x%x\n", versionIdentifier)
		fmt.Printf("Bus Number: 0x%x\n", busNumber)

		// Mask out the
		clientIdentifier := binary.BigEndian.Uint64(b[8:16])
		fmt.Printf("Client Identifier: 0x%x\n", clientIdentifier)

		canId := binary.BigEndian.Uint32(b[16:20])
		fmt.Printf("CAN ID: 0x%x\n", canId)

		flags := b[20]
		flagHeartbeat := (flags>>7)&uint8(1) == 1
		flagSettings := (flags>>6)&uint8(1) == 1
		flagRtr := (flags>>1)&uint8(1) == 1
		flagExtendedId := (flags>>0)&uint8(1) == 1
		fmt.Printf("Flags: 0x%x\n", flags)
		fmt.Printf("Heartbeat: %t\n", flagHeartbeat)
		fmt.Printf("Settings: %t\n", flagSettings)
		fmt.Printf("RTR: %t\n", flagRtr)
		fmt.Printf("Extended: %t\n", flagExtendedId)

		length := b[21]
		fmt.Printf("Length: 0x%x\n", length)

		data := binary.BigEndian.Uint64(b[22:30])
		fmt.Printf("Data: 0x%x\n", data)
	}
}
