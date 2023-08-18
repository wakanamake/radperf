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

type Config struct {
	NumPackets      int
	Secret          string
	IP4Addr         netip.Addr
	IP6Net          netip.Prefix
	Rate            int
	UsernamePrefix  string
	MSISDN          int
	ServicePlan     string
	SessionIDPrefix string
	accttype        rfc2866.AcctStatusType
}

func main() {
	var (
		ip4       string
		ip6       string
		start     bool
		stop      bool
		sessionId string
		destIP    string
		destPort  int
		config    Config
	)

	// Define the flags
	flag.IntVar(&config.NumPackets, "n", 1, "Number of packets to send")
	flag.IntVar(&config.Rate, "r", 1, "Rate of packet transmission (packets per second)")
	flag.StringVar(&destIP, "d", "127.0.0.1", "Destination IP address")
	flag.IntVar(&destPort, "p", 1813, "Destination UDP port")
	flag.StringVar(&config.Secret, "s", "secret", "RADIUS secret")
	flag.StringVar(&ip4, "i", "", "Client IP address (Framed-IP-Address Attribute)")
	flag.StringVar(&ip6, "i6", "", "Client IPv6 prefix (Framed-IPv6-Prefix Attribute)")
	flag.StringVar(&config.ServicePlan, "sp", "Default Service Plan", "Service Plan name (Class Attribute)")
	flag.StringVar(&sessionId, "sid", "", "Session ID prefix (Default: random strings)")
	flag.IntVar(&config.MSISDN, "m", 12345678, "MSISDN (Calling-Station-Id Attribute)")
	flag.StringVar(&config.UsernamePrefix, "user", "HOGE", "Username prefix")
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

	if ip4 == "" && ip6 == "" {
		fmt.Println("Error: Either IPv4 or IPv6 address must be specified.")
		return
	}

	if ip6 != "" {
		ip, err := netip.ParsePrefix(ip6)
		if err != nil {
			fmt.Printf("Could not parse IPv6 prefix: %s\n", ip6)
			return
		}
		config.IP6Net = ip
	}

	if ip4 != "" {
		ip, err := netip.ParseAddr(ip4)
		if err != nil {
			fmt.Printf("Could not parse IP address: %s\n", ip4)
			return
		}
		config.IP4Addr = ip
	}

	if !start && !stop {
		fmt.Println("Error: Either 'start' or 'stop' option must be specified.")
		return
	}

	// Decide Accounting Status Type
	if start {
		config.accttype = rfc2866.AcctStatusType_Value_Start
	} else if stop {
		config.accttype = rfc2866.AcctStatusType_Value_Stop
	}

	serverIP, err := netip.ParseAddr(destIP)
	if err != nil {
		fmt.Printf("Could not parse IP address: %s\n", destIP)
		return
	}

	// Dial a UDP connection.
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IP(serverIP.AsSlice()),
		Port: destPort,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	if sessionId == "" {
		config.SessionIDPrefix = GenerateRandomString(6)
	} else {
		config.SessionIDPrefix = sessionId
	}

	sendRADIUSmessages(conn, config)
}

func sendRADIUSmessages(conn *net.UDPConn, config Config) {
	for i := 0; i < config.NumPackets; i++ {
		packet := radius.New(radius.CodeAccountingRequest, []byte(config.Secret))
		username := fmt.Sprintf("%s%08d", config.UsernamePrefix, i)
		sessionID := fmt.Sprintf("%s%08d", config.SessionIDPrefix, i)

		// Set Attributes
		rfc2865.UserName_SetString(packet, username)
		rfc2866.AcctSessionID_SetString(packet, sessionID)

		if config.IP4Addr.Is4() == true {
			rfc2865.FramedIPAddress_Add(packet, net.IP(config.IP4Addr.AsSlice()))
			config.IP4Addr = config.IP4Addr.Next()
		}
		if config.IP6Net.Addr().Is6() == true {
			rfc3162.FramedIPv6Prefix_Add(packet, prefixToIPNet(config.IP6Net))
			config.IP6Net = incrementIPv6Prefix(config.IP6Net)
		}
		rfc2865.CallingStationID_SetString(packet, strconv.Itoa(config.MSISDN))
		config.MSISDN++

		rfc2865.Class_SetString(packet, config.ServicePlan)
		rfc2866.AcctStatusType_Add(packet, config.accttype)

		sendUDPPacket(conn, packet)
	}

	fmt.Println("Sending RADIUS Accounting messages completed.")
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

func prefixToIPNet(prefix netip.Prefix) *net.IPNet {
	ip := prefix.Addr()
	mask := net.CIDRMask(prefix.Bits(), 128)
	return &net.IPNet{
		IP:   net.IP(ip.AsSlice()),
		Mask: mask,
	}
}

func incrementIPv6Prefix(ip6 netip.Prefix) netip.Prefix {
	prefixSize := ip6.Bits()

	// Convert the IPv6 to a big integer.
	ipInt := big.NewInt(0)
	ipInt.SetBytes(ip6.Addr().AsSlice())

	// Calculate the number of bits to shift based on the prefix length.
	shiftBits := 128 - prefixSize

	// Create the increment value.
	increment := big.NewInt(1)
	increment.Lsh(increment, uint(shiftBits))

	// Add the increment to the big integer.
	ipInt.Add(ipInt, increment)

	// Get netip.Prefix from bytes and prefixsize
	addr, _ := netip.AddrFromSlice(ipInt.Bytes())
	ip, err := netip.ParsePrefix(addr.String() + fmt.Sprintf("/%d", prefixSize))
	if err != nil {
		log.Fatalf("Could not parse IPv6 prefix: %v", err)
	}

	return ip
}
