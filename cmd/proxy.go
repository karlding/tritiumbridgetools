package cmd

import (
	"github.com/spf13/cobra"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"github.com/BurntSushi/toml"

	"github.com/karlding/tritiumbridgetools/tritium"

	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// BridgeConfig contains all the configuration for a particular Tritium Bridge
type BridgeConfig struct {
	ID                 uint8  `toml:"id"`
	IP                 string `toml:"ip"`
	NetworkInterface   string `toml:"network_interface"`
	SocketCANInterface string `toml:"vcan"`
}

// Config contains the representation of a TOML file describing the network
type Config struct {
	Bridge []BridgeConfig `toml:"bridge"`
}

// Transport is the type of network transport (TCP/UDP) used to communicate
// with the Tritium CAN-Ethernet bridge
var Transport string

var tomlFile string

func init() {
	log.SetOutput(os.Stdout)

	rootCmd.AddCommand(proxyCommand)

	proxyCommand.Flags().StringVarP(&Transport, "transport", "t", "", "Transport source [tcp,udp]")
	proxyCommand.MarkFlagRequired("transport")

	proxyCommand.Flags().StringVarP(&tomlFile, "config", "f", "", "TOML file")
	proxyCommand.MarkFlagRequired("config")
}

var proxyCommand = &cobra.Command{
	Use:   "proxy",
	Short: "",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
		doStuff()
	},
}

func handleUDPPackets(packetConn *ipv4.PacketConn, socketMap map[uint8]int) {
	// (64 + 8 + 8 + 32 + 56 + 8 + 56 + 8) bits = 30 bytes
	b := make([]byte, 30)

	for {
		numBytes, _, _, err := packetConn.ReadFrom(b)
		if err != nil {
			// error handling
			continue
		}

		if numBytes != 30 {
			log.Println(b)
			panic("Failed")
		}

		tritiumPacket := new(tritium.Packet)
		tritium.ByteArrayToTritiumMessage(b, tritiumPacket)

		// Now forward onto SocketCAN interface if it isn't a Heartbeat frame
		if !tritiumPacket.FlagHeartbeat {
			sendFrame := make([]byte, 16)
			tritium.PacketToSocketCANFrame(tritiumPacket, sendFrame)

			// Find the socket by bus number
			if fd, ok := socketMap[tritiumPacket.BusNumber]; ok {
				unix.Write(fd, sendFrame)
			}
		}
	}
}

func doStuffOverUDP(conf Config) {
	// The Group Address is 239.255.60.60
	group := net.IPv4(239, 255, 60, 60)

	// socketMap[Bus Number] = SocketCAN file descriptor
	socketMap := make(map[uint8]int)

	// Start a UDP connection
	// The Tritium CAN-Ethernet bridge always broadcasts on port 4876
	// TODO: Should we only bind on a single interface?
	c, err := net.ListenPacket("udp4", "0.0.0.0:4876")
	if err != nil {
		// error handling
		return
	}
	defer c.Close()

	// Join UDP Multicast group
	// This can be verified by checking the groups you belong to:
	// 	netstat -gn | grep '239.255.60.60'
	p := ipv4.NewPacketConn(c)

	for _, bridge := range conf.Bridge {
		vcan, err := net.InterfaceByName(bridge.SocketCANInterface)
		if err != nil {
			log.Fatal(err)
			return
		}

		fd, err := unix.Socket(unix.AF_CAN, unix.SOCK_RAW, unix.CAN_RAW)
		if err != nil {
			return
		}

		addr := &unix.SockaddrCAN{Ifindex: vcan.Index}
		socketMap[bridge.ID] = fd
		unix.Bind(fd, addr)

		networkInterface, err := net.InterfaceByName(bridge.NetworkInterface)
		if err != nil {
			log.Fatal(err)
			return
		}
		// TODO: Error handling for this..
		// Probably handle failing case with random padded
		macAddressBuffer := networkInterface.HardwareAddr
		macAddress := binary.LittleEndian.Uint64(macAddressBuffer[0:8])

		if err := p.JoinGroup(networkInterface, &net.UDPAddr{IP: group}); err != nil {
			// error handling
			return
		}

		// Start a goroutine for each SocketCAN interface to forward over UDP
		go func(fd int, packetConn *ipv4.PacketConn, macAddress uint64) {
			rxBuff := make([]byte, 16)
			txBuff := make([]byte, 30)
			networkInterface, err := net.InterfaceByName(bridge.NetworkInterface)
			if err != nil {
				log.Fatal(err)
				return
			}

			for {
				// (64 + 8 + 8 + 32 + 56 + 8 + 56 + 8) bits = 30 bytes
				numBytes, err := unix.Read(fd, rxBuff[:])
				log.Println("kralyoloasdf", rxBuff)
				if err != nil {
					continue
				}
				if numBytes != 16 {
					panic("numBytes was not 16 bytes")
				}

				tritiumPacket := new(tritium.Packet)
				tritium.SocketCANToTritiumPacket(rxBuff, tritiumPacket, uint64(0x5472697469756), 0xd, macAddress)

				tritium.PacketToNetworkByteArray(tritiumPacket, txBuff)

				// Send multicast packet to group
				// TODO: is it necessary to specify a control message?
				bytes, err := packetConn.WriteTo(txBuff, &ipv4.ControlMessage{IfIndex: networkInterface.Index}, &net.UDPAddr{IP: group, Port: 4876})
				if err != nil {
					panic(err)
				}
				if bytes != 30 {
					log.Printf("Only wrote %d bytes\n", bytes)
				}
			}
		}(fd, p, macAddress)
	}

	go handleUDPPackets(p, socketMap)

	select {}
}

func doStuffOverTCP(conf Config) {
	// In TCP mode, we need to send:
	//
	// +-----------------------------+
	// | Fwd Identifier (32 bits)    |
	// +-----------------------------+
	// | Fwd range (32 bits)         |
	// +-----------------------------+
	// | Padding (8 bits)            |
	// +-----------------------------+
	// | Bus Identifier (56 bits)    |
	// +-----------------------------+
	// | Padding (8 bits)            |
	// +-----------------------------+
	// | Client Identifier (56 bits) |
	// +-----------------------------+
	for _, bridge := range conf.Bridge {
		vcan, err := net.InterfaceByName(bridge.SocketCANInterface)
		if err != nil {
			log.Fatal(err)
			return
		}

		fd, err := unix.Socket(unix.AF_CAN, unix.SOCK_RAW, unix.CAN_RAW)
		if err != nil {
			return
		}

		addr := &unix.SockaddrCAN{Ifindex: vcan.Index}
		unix.Bind(fd, addr)

		networkInterface, err := net.InterfaceByName(bridge.NetworkInterface)
		if err != nil {
			log.Fatal(err)
			return
		}

		setupBuffer := make([]byte, (4 + 4 + 1 + 7 + 1 + 7))

		// The bridge will forward any packet matching:
		//
		// 		fwdIdentifier <= CAN arbitration id < (fwdIdentifier + fwdRange)
		//
		// So we set the bridge to forward all valid CAN IDs (including extended),
		// which is the range [0, 2^29 - 1]
		fwdIdentifier := uint32(0)
		fwdRange := uint32(536870911)
		// The Bus Number must match the Bus Number specified in the Tritium
		// CAN-Ethernet Bridge Configuration tool, otherwise the TCP connection is
		// terminated.
		// TODO: Take these as configuration options?
		busIdentifier := (uint64(0x5472697469756) << 4) | uint64(0xd)

		binary.BigEndian.PutUint32(setupBuffer[0:4], fwdIdentifier)
		binary.BigEndian.PutUint32(setupBuffer[4:8], fwdRange)
		binary.BigEndian.PutUint64(setupBuffer[8:16], busIdentifier)
		// TODO: We probably need error checking here in case the MAC address
		// is not 8 bytes?
		copy(setupBuffer[16:24], networkInterface.HardwareAddr[0:8])
		macAddressBuffer := networkInterface.HardwareAddr
		macAddress := binary.LittleEndian.Uint64(macAddressBuffer[0:8])

		// Establish a TCP connection
		// TODO: Handle multiple Tritium bridges on the same subnet.
		bridgeIPAddress := net.ParseIP(bridge.IP)
		conn, err := net.Dial("tcp4", fmt.Sprintf("%s:4876", bridgeIPAddress.String()))
		if err != nil {
			log.Println(err)
			return
		}

		// Send fwd identifiers for every message
		// TODO: Maybe we want to support selectively sending fwd identifiers?
		bytes, err := conn.Write(setupBuffer)
		log.Println(bytes)
		if err != nil {
			log.Println(err)
			return
		}

		// Start a goroutine for each bridge we're receiving from
		go func(conn net.Conn, fd int) {
			b := make([]byte, 30)
			// (64 + 8 + 8 + 32 + 56 + 8 + 56 + 8) bits = 30 bytes
			numBytes, err := io.ReadFull(conn, b[:])
			if err != nil {
				// error handling
				log.Println(err)
				return
			}

			if numBytes != 30 {
				log.Println(b)
				panic("Failed")
			}

			tritiumPacket := new(tritium.Packet)
			tritium.ByteArrayToTritiumMessage(b, tritiumPacket)

			// Now forward onto SocketCAN interface if it isn't a Heartbeat frame
			if !tritiumPacket.FlagHeartbeat {
				sendFrame := make([]byte, 16)
				tritium.PacketToSocketCANFrame(tritiumPacket, sendFrame)
				// Find the socket by bus number
				unix.Write(fd, sendFrame)
			}

			// Subsequent packets are 14 bytes
			buff := make([]byte, 14)
			for {
				// (64 + 8 + 8 + 32 + 56 + 8 + 56 + 8) bits = 30 bytes
				numBytes, err := io.ReadFull(conn, buff[:])
				log.Printf("Received %d bytes\n", numBytes)
				for i, val := range buff {
					log.Printf("buff[%d] = 0x%x\n", i, val)
				}
				if err != nil {
					// error handling
					log.Println(err)
					continue
					panic("Failed")
				}

				if numBytes != 14 {
					log.Println(buff)
					panic("Failed")
				}

				tritiumPacket := new(tritium.Packet)
				tritium.ByteArrayTCPToTritiumMessage(buff, tritiumPacket)

				// Now forward onto SocketCAN interface if it isn't a Heartbeat frame
				if !tritiumPacket.FlagHeartbeat {
					sendFrame := make([]byte, 16)
					tritium.PacketToSocketCANFrame(tritiumPacket, sendFrame)
					// Find the socket by bus number
					unix.Write(fd, sendFrame)
				}
			}
		}(conn, fd)

		// Forward from SocketCAN interface over TCP
		go func(socketCanFd int, packetConn net.Conn, macAddress uint64) {
			rxBuff := make([]byte, 16)
			txBuff := make([]byte, 30)

			for {
				// Read from SocketCAN interface
				// (64 + 8 + 8 + 32 + 56 + 8 + 56 + 8) bits = 30 bytes
				numBytes, err := unix.Read(socketCanFd, rxBuff[:])
				log.Println("kralyoloasdf", rxBuff)
				if err != nil {
					continue
				}
				if numBytes != 16 {
					panic("numBytes was not 16 bytes")
				}

				tritiumPacket := new(tritium.Packet)
				tritium.SocketCANToTritiumPacket(rxBuff, tritiumPacket, uint64(0x5472697469756), 0xd, macAddress)

				tritium.PacketToNetworkByteArray(tritiumPacket, txBuff)

				// We skip the headers that aren't needed:
				//
				// * Bus Identifier: 8 bytes
				// * Client Identifier: 8 bytes
				bytes, err := packetConn.Write(txBuff[16:])
				if err != nil {
					panic(err)
				}
				if bytes != 30 {
					log.Printf("Only wrote %d bytes\n", bytes)
				}
			}
		}(fd, conn, macAddress)
	}

	select {}
}

func doStuff() {
	// Set GitCommit and Version
	var conf Config

	// TOML parsing
	toml.DecodeFile(tomlFile, &conf)

	if Transport == "udp" {
		doStuffOverUDP(conf)
	} else if Transport == "tcp" {
		doStuffOverTCP(conf)
	}
}
