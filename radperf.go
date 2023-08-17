package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"
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
	"layeh.com/radius/rfc3162"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func main() {
	var (
		numPackets     int
		secret         string
		ip             string
		ip6prefix      string
		rate           int
		destIP         string
		destPort       int
		usernamePrefix string
		msisdn         int
		start          bool
		stop           bool
		servicePlan    string
		sessionId      string
	)

	// Define the flags
	flag.IntVar(&numPackets, "n", 1, "Number of packets to send")
	flag.IntVar(&rate, "r", 1, "Rate of packet transmission (packets per second)")
	flag.StringVar(&destIP, "d", "127.0.0.1", "Destination IP address")
	flag.IntVar(&destPort, "p", 1813, "Destination UDP port")
	flag.StringVar(&secret, "s", "secret", "RADIUS secret")
	flag.StringVar(&ip, "i", "192.168.0.1", "Client IP address (Framed-IP-Address Attribute)")
	flag.StringVar(&ip6prefix, "i6", "fec0::/64", "Client IPv6 prefix (Framed-IPv6-Prefix Attribute)")
	flag.StringVar(&servicePlan, "sp", "Default Service Plan", "Service Plan name (Class Attribute)")
	flag.StringVar(&sessionId, "sid", "", "Session ID prefix (Default: random strings)")
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

	var ip6Net *net.IPNet

	if ip6prefix != "" {
		_, ipNet, err := net.ParseCIDR(ip6prefix)
		if err != nil {
			return
		}
		ip6Net = ipNet
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

	var sessionIDPrefix string

	if sessionId == "" {
		sessionIDPrefix = GenerateRandomString(6)
	} else {
		sessionIDPrefix = sessionId
	}

	for i := 0; i < numPackets; i++ {
		packet := radius.New(radius.CodeAccountingRequest, []byte(secret))
		username := fmt.Sprintf("%s%08d", usernamePrefix, id)
		sessionID := fmt.Sprintf("%s%08d", sessionIDPrefix, id)
		// Attributes
		rfc2865.UserName_SetString(packet, username)
		rfc2866.AcctSessionID_SetString(packet, sessionID)
		rfc2865.FramedIPAddress_Add(packet, net.IP(startIP.AsSlice()))
		rfc3162.FramedIPv6Prefix_Add(packet, ip6Net)
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
		ip6Net = incrementIPv6Prefix(ip6Net)
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

func incrementIPv6Prefix(ip6 *net.IPNet) *net.IPNet {
	ip := ip6.IP
	prefixSize, _ := ip6.Mask.Size()

	// Convert the IPv6 to a big integer.
	ipInt := big.NewInt(0)
	ipInt.SetBytes(ip.To16())

	// Calculate the number of bits to shift based on the prefix length.
	shiftBits := 128 - prefixSize

	// Create the increment value.
	increment := big.NewInt(1)
	increment.Lsh(increment, uint(shiftBits))

	// Add the increment to the big integer.
	ipInt.Add(ipInt, increment)

	_, netIP, _ := net.ParseCIDR(net.IP(ipInt.Bytes()).String() + fmt.Sprintf("/%d", prefixSize))

	return netIP
}
