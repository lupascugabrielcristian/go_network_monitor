package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/IbrahimShahzad/gonfigure"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Fac map de obiecte de tip IP la uint32
// Vreau sa tin aici ip-urile care raspund
var arp_reply_sources []net.IP

var tcp_source_ips []string
var tcp_dest_ips []string

func main() {
	fmt.Println("Reading config file /tmp/go_mon_conf.ini")
	objINI, err := gonfigure.LoadINI("/tmp/go_mon_conf.ini")

	if err != nil {
		panic("Config file not found. Should be /tmp/go_mon_conf.ini")
	}

	// NETWORK INTERFACE
	ntwkInterface, err := gonfigure.GetParameterValue(objINI, "Monitor", "interface")
	if err != nil {
		panic("Config value 'interface' from 'Monitor' section not found")
	}

	numPackets := 0
	numPacketsStr, err := gonfigure.GetParameterValue(objINI, "General", "num_packets")
	if err == nil {
		val, errConv := strconv.Atoi(numPacketsStr)
		if errConv == nil {
			numPackets = val
		}
	}
	fmt.Printf("Scanning %v packets\n", numPackets)

	handle, err := pcap.OpenLive(ntwkInterface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	arp_reply_sources = make([]net.IP, 0)
	counter := 0
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		counter += 1
		handlePacket(packet)
		fmt.Printf("\r%v/%v", counter, numPackets)

		if counter == numPackets {
			break
		}
	}

	fmt.Println(arp_reply_sources)
	fmt.Println(tcp_source_ips)
	fmt.Println(tcp_dest_ips)
	fmt.Println("gata")
}

func handlePacket(packet gopacket.Packet) {

	if packet.Layer(layers.LayerTypeTCP) != nil {
		handleTCPPacket(packet)
	} else if packet.Layer(layers.LayerTypeARP) != nil {
		handleARPPacket(packet)
	} else {
		// printLayers( packet )
	}

}

// Listez toate layer-urile disponibile pentru acest packet
func printLayers(packet gopacket.Packet) {
	layerNames := make([]string, 0)
	for _, layer := range packet.Layers() {
		layerNames = append(layerNames, layer.LayerType().String())
	}
	fmt.Println(strings.Join(layerNames, " "))
}

// TCP PACKETS
func handleTCPPacket(packet gopacket.Packet) {
	//printLayers( packet )

	// tcpLayer := packet.Layer(layers.LayerTypeTCP)
	// tcp, _ := tcpLayer.(*layers.TCP)

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	ipv4, _ := ipv4Layer.(*layers.IPv4)
	// srcIp := strings.Replace( ipv4.SrcIP.String(), " ", ".", -1 )
	// dstIp := strings.Replace( ipv4.DstIP.String(), " ", ".", -1 )
	// fmt.Printf("TCP packet from %d:%d to destination %d:%d\n", srcIp, tcp.SrcPort, dstIp, tcp.DstPort)

	srcIPStr := ipToString(ipv4.SrcIP, numberToString)
	dstIPStr := ipToString(ipv4.DstIP, numberToString)

	// Caut daca exista deja
	ipFound := false
	for _, value := range tcp_source_ips {
		if value == srcIPStr {
			ipFound = true
			break
		}
	}

	if !ipFound {
		tcp_source_ips = append(tcp_source_ips, srcIPStr)
		fmt.Printf("\rTCP %d -> %d\n", ipv4.SrcIP, ipv4.DstIP)
	}

	// Caut daca exista deja
	ipFound = false
	for _, value := range tcp_dest_ips {
		if value == dstIPStr {
			ipFound = true
			break
		}
	}

	if !ipFound {
		tcp_dest_ips = append(tcp_dest_ips, dstIPStr)
		fmt.Printf("\rTCP %d -> %d\n", ipv4.SrcIP, ipv4.DstIP)
	}

}

// ARP PACKETS
func handleARPPacket(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	arp, _ := arpLayer.(*layers.ARP)

	if arp.Operation == 1 {
		// ARP Request
		//fmt.Printf("Machine %v vrea sa stie MAC pentru %v\n", arp.SourceProtAddress, arp.DstProtAddress)
	} else {
		// ARP Reply
		//fmt.Println("ARP Reply")

		// Caut daca exista deja
		ipFound := false
		for _, value := range arp_reply_sources {
			if value[3] == arp.SourceProtAddress[3] {
				ipFound = true
				break
			}
		}

		if !ipFound {
			// Imi face alt slice aici
			arp_reply_sources = append(arp_reply_sources, arp.SourceProtAddress)
			fmt.Printf("\r%v a raspuns ca are MAC %v\n", arp.SourceProtAddress, arp.SourceHwAddress)
		}
	}
}

func ipToString(ip net.IP, f func(byte) string) string {
	res := ""

	for _, val := range ip {
		res += f(val)
		res += "."
	}

	return res
}

func numberToString(number byte) string {
	return strconv.Itoa(int(number))
}
