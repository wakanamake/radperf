package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

func main() {
	var (
		numPackets int
		secret     string
		ip         string
		rate       int
		destIP     string
		destPort   int
		username   string
		sessionID  string
		msisdn     string
		start      bool
		stop       bool
	)

	// Define the flags
	flag.IntVar(&numPackets, "n", 1, "Number of packets to send")
	flag.StringVar(&secret, "s", "secret", "RADIUS secret")
	flag.StringVar(&ip, "i", "192.168.0.1", "Client IP address with prefix size (CIDR notation)")
	flag.IntVar(&rate, "r", 1, "Rate of packet transmission (packets per second)")
	flag.StringVar(&destIP, "d", "127.0.0.1", "Destination IP address")
	flag.IntVar(&destPort, "p", 1813, "Destination UDP port")
	flag.StringVar(&msisdn, "m", "01012345678", "MSISDN value")
	flag.StringVar(&username, "user", "HOGE", "Username prefix")
	flag.StringVar(&sessionID, "sid", "0123", "Session ID prefix")
	flag.BoolVar(&start, "start", false, "Allow to send Accounting START message")
	flag.BoolVar(&stop, "stop", false, "Allow to send Accounting STOP message")

	// Define custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(os.Stderr, "Options:")
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "  -%s %s (default: %v)\n", f.Name, f.Usage, f.DefValue)
		})
	}

	// Parse command line arguments
	flag.Parse()

	// Show usage if no arguments are provided
	if flag.NFlag() == 0 {
		flag.Usage()
		return
	}

	startIP, err := netip.ParseAddr(ip)
	if err != nil {
		fmt.Printf("Could not parse IP address: %s\n", ip)
		return
	}

	serverIP, err := netip.ParseAddr(destIP)
	if err != nil {
		fmt.Printf("Could not parse IP address: %s\n", destIP)
		return
	}
	//dest := net.ParseIP(serverIP.String())
	dest := net.IP(serverIP.AsSlice())
	if dest == nil {
		fmt.Println("Invalid destination IP address:", destIP)
		return
	}

	// Dial a UDP connection.
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   dest,
		Port: destPort,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	for i := 0; i < numPackets; i++ {
		packet := radius.New(radius.CodeAccountingRequest, []byte(secret))

		// Attributes
		rfc2865.UserName_SetString(packet, "HOGE")
		rfc2866.AcctSessionID_SetString(packet, "1234567890")
		rfc2866.AcctStatusType_Add(packet, rfc2866.AcctStatusType_Value_Start)
		rfc2865.FramedIPAddress_Add(packet, net.IP(startIP.AsSlice()))
		rfc2865.CallingStationID_SetString(packet, msisdn)

		encodedPacket, err := packet.Encode()
		if err != nil {
			log.Fatalf("Error encoding packet: %v", err)
		}
		// Write the packet to the RADIUS server.
		_, err = conn.Write(encodedPacket)
		if err != nil {
			log.Fatalf("Error writing: %v", err)
		}
		startIP = startIP.Next()
	}

	fmt.Println("RADIUS Accounting Start messages sent.")
}
