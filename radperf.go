package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func main() {
	var (
		numPackets     int
		secret         string
		ip             string
		rate           int
		destIP         string
		destPort       int
		usernamePrefix string
		msisdn         int
		start          bool
		stop           bool
		servicePlan    string
	)

	// Define the flags
	flag.IntVar(&numPackets, "n", 1, "Number of packets to send")
	flag.IntVar(&rate, "r", 1, "Rate of packet transmission (packets per second)")
	flag.StringVar(&destIP, "d", "127.0.0.1", "Destination IP address")
	flag.IntVar(&destPort, "p", 1813, "Destination UDP port")
	flag.StringVar(&secret, "s", "secret", "RADIUS secret")
	flag.StringVar(&ip, "i", "192.168.0.1", "Client IP address (Framed-IP-Address Attribute)")
	flag.StringVar(&servicePlan, "sp", "Default Service Plan", "Service Plan name (Class Attribute)")
	flag.IntVar(&msisdn, "m", 12345678, "MSISDN (Calling-Station-Id Attribute)")
	flag.StringVar(&usernamePrefix, "user", "HOGE", "Username prefix")
	flag.BoolVar(&start, "start", false, "Send Accounting START message")
	flag.BoolVar(&stop, "stop", false, "Send Accounting STOP message")

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

	if !start && !stop {
		fmt.Println("Error: Either 'start' or 'stop' option must be specified.")
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

	id := 0
	sessionIDPrefix := GenerateRandomString(6)

	for i := 0; i < numPackets; i++ {
		packet := radius.New(radius.CodeAccountingRequest, []byte(secret))
		username := fmt.Sprintf("%s%08d", usernamePrefix, id)
		sessionID := fmt.Sprintf("%s%08d", sessionIDPrefix, id)
		// Attributes
		rfc2865.UserName_SetString(packet, username)
		rfc2866.AcctSessionID_SetString(packet, sessionID)
		rfc2865.FramedIPAddress_Add(packet, net.IP(startIP.AsSlice()))
		rfc2865.CallingStationID_SetString(packet, strconv.Itoa(msisdn))
		rfc2865.Class_SetString(packet, servicePlan)

		if start {
			rfc2866.AcctStatusType_Add(packet, rfc2866.AcctStatusType_Value_Start)
		} else if stop {
			rfc2866.AcctStatusType_Add(packet, rfc2866.AcctStatusType_Value_Stop)
		}
		sendUDPPacket(conn, packet)

		id++
		msisdn++
		startIP = startIP.Next()
	}

	fmt.Println("RADIUS Accounting Start messages sent.")
}

func GenerateRandomString(n int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[r.Intn(len(letterRunes))]
	}
	return string(b)
}

func sendUDPPacket(conn *net.UDPConn, packet *radius.Packet) {
	// Encode the pakcet
	encodedPacket, err := packet.Encode()
	if err != nil {
		log.Fatalf("Error encoding packet: %v", err)
	}
	// Write the packet to the RADIUS server.
	_, err = conn.Write(encodedPacket)
	if err != nil {
		log.Fatalf("Error writing: %v", err)
	}
}
