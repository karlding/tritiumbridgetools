package main

import (
	"flag"
	"fmt"
	"golang.org/x/net/ipv4"
	"log"
	"net"
)

func main() {
	flag.Parse()
	fmt.Println("tail: ", flag.Args())

	// The Tritium CAN-Ethernet bridge always broadcasts on port 4876
	// The Group Address is 239.255.60.60
	enp0s25, err := net.InterfaceByName("enp0s25")
	if err != nil {
		log.Fatal(err)
	}
	group := net.IPv4(239, 255, 60, 60)

	c, err := net.ListenPacket("udp4", "0.0.0.0:4876")
	if err != nil {
		// error handling
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(enp0s25, &net.UDPAddr{IP: group}); err != nil {
		// error handling
	}

	b := make([]byte, 1500)
	for {
		_, _, _, err := p.ReadFrom(b)
		if err != nil {
			// error handling
		}
		fmt.Println("yolo")
	}
}
