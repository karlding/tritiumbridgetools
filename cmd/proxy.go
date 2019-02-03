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

// InterfaceName is the interface to listen on
var InterfaceName string

var bridgeAddress string
var bridge map[string]string

func init() {
	log.SetOutput(os.Stdout)

	rootCmd.AddCommand(proxyCommand)

	proxyCommand.Flags().StringVarP(&Transport, "transport", "t", "", "Transport source [tcp,udp]")
	proxyCommand.MarkFlagRequired("transport")

	proxyCommand.Flags().StringVarP(&InterfaceName, "interface", "i", "", "Network interface to listen on")
	proxyCommand.MarkFlagRequired("interface")

	proxyCommand.Flags().StringToStringVar(&bridge, "bridge", nil, "Bridge mapping")
	proxyCommand.MarkFlagRequired("bridge")

	proxyCommand.Flags().StringVarP(&bridgeAddress, "bridgeaddress", "p", "", "Bridge IP address")
	proxyCommand.MarkFlagRequired("bridgeaddress")
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

func doStuffOverUDP(fd int, networkInterface *net.Interface) {
	addrs, _ := networkInterface.Addrs()
	for _, addr := range addrs {
		log.Printf("UDP IP: %s\n", addr.String())
	}
	// The Group Address is 239.255.60.60
	group := net.IPv4(239, 255, 60, 60)

	// Start a UDP connection
	// The Tritium CAN-Ethernet bridge always broadcasts on port 4876
	// TODO: Find the IP address on the provided interface
	// MulticastAddrs
	c, err := net.ListenPacket("udp4", "0.0.0.0:4876")
	// Otherwise we can use TCP
	if err != nil {
		// error handling
		return
	}
	defer c.Close()

	// Join UDP Multicast group
	// This can be verified by checking the groups you belong to:
	// 	netstat -gn | grep '239.255.60.60'
	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(networkInterface, &net.UDPAddr{IP: group}); err != nil {
		// error handling
		return
	}

	go func() {
		b := make([]byte, 30)
		for {
			// (64 + 8 + 8 + 32 + 56 + 8 + 56 + 8) bits = 30 bytes
			numBytes, _, addr, err := p.ReadFrom(b)
			log.Printf("Received %d bytes\n", numBytes)
			log.Printf("Address: %s\n", addr.String())
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
				unix.Write(fd, sendFrame)
			}
		}
	}()

	select {}
}

func doStuffOverTCP(fd int, networkInterface *net.Interface) {
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
	macAddress := networkInterface.HardwareAddr
	copy(setupBuffer[16:24], macAddress[0:8])

	// Establish a TCP connection
	// TODO: Handle multiple Tritium bridges on the same subnet.
	bridgeIPAddress := net.ParseIP(bridgeAddress)
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

	b := make([]byte, 30)
	// (64 + 8 + 8 + 32 + 56 + 8 + 56 + 8) bits = 30 bytes
	numBytes, err := io.ReadFull(conn, b[:])
	log.Printf("Received %d bytes\n", numBytes)
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

	log.Printf("CAN Id: %d\n", tritiumPacket.CanID)
	log.Printf("Bus Number: 0x%x\n", tritiumPacket.BusNumber)
	log.Printf("Client Identifier: 0x%x\n", tritiumPacket.ClientIdentifier)
	log.Printf("Heartbeat: %t\n", tritiumPacket.FlagHeartbeat)
	log.Printf("Settings: %t\n", tritiumPacket.FlagSettings)
	log.Printf("RTR: %t\n", tritiumPacket.FlagRtr)
	log.Printf("Extended: %t\n", tritiumPacket.FlagExtendedID)
	log.Printf("Length: 0x%x\n", tritiumPacket.Length)
	log.Printf("Data: 0x%x\n", tritiumPacket.Data)

	// Now forward onto SocketCAN interface if it isn't a Heartbeat frame
	if !tritiumPacket.FlagHeartbeat {
		sendFrame := make([]byte, 16)
		tritium.PacketToSocketCANFrame(tritiumPacket, sendFrame)
		// Find the socket by bus number
		unix.Write(fd, sendFrame)
	}

	go func() {
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
	}()

	select {}
}

func doStuff() {
	// Set GitCommit and Version
	log.Println(bridge)

	var conf Config

	// TOML parsing
	toml.DecodeFile("example.toml", &conf)
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

		log.Printf("bridge.ID: 0x%x\n", bridge.ID)
		log.Printf("bridge.IP: %s\n", bridge.IP)
		log.Printf("bridge.NetworkInterface: %s\n", bridge.NetworkInterface)
		log.Printf("bridge.SocketCANInterface: %s\n", bridge.SocketCANInterface)

		// TODO: Does Cobra have a native way of doing enumerated strings?
		if Transport == "udp" {
			doStuffOverUDP(fd, networkInterface)
		} else if Transport == "tcp" {
			doStuffOverTCP(fd, networkInterface)
		}
	}

}
