package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/IbrahimShahzad/gonfigure"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
)

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

	counter := 0
	packetSource := gopacket.NewPacketSource( handle, handle.LinkType() )
	for packet := range packetSource.Packets() {
		counter += 1
		handlePacket(packet)

		if counter == numPackets {
			break
		}
	}

	fmt.Println("gata")
}

func handlePacket(packet gopacket.Packet) {

	if packet.Layer( layers.LayerTypeTCP) != nil {
		// handleTCPPacket( packet )
	} else if packet.Layer( layers.LayerTypeARP) != nil {
		handleARPPacket( packet )
	} else {
		// printLayers( packet )
	}

}

// Listez toate layer-urile disponibile pentru acest packet
func printLayers( packet gopacket.Packet ) {
	layerNames := make([]string, 0)
	for _, layer := range packet.Layers() {
		layerNames = append( layerNames, layer.LayerType().String() )
	}
	fmt.Println( strings.Join( layerNames, " " ))
}

// TCP PACKETS
func handleTCPPacket( packet gopacket.Packet ) {
	//printLayers( packet )

	tcpLayer := packet.Layer( layers.LayerTypeTCP )
	tcp, _ := tcpLayer.(*layers.TCP)

	ipv4Layer := packet.Layer( layers.LayerTypeIPv4 )
	ipv4, _ := ipv4Layer.(*layers.IPv4)
	srcIp := strings.Replace( ipv4.SrcIP.String(), " ", ".", -1 )
	dstIp := strings.Replace( ipv4.DstIP.String(), " ", ".", -1 )
	fmt.Printf("TCP packet from %d:%d to destination %d:%d\n", srcIp, tcp.SrcPort, dstIp, tcp.DstPort)
}

// ARP PACKETS
func handleARPPacket( packet gopacket.Packet ) {
	arpLayer := packet.Layer( layers.LayerTypeARP )
	arp, _ := arpLayer.(*layers.ARP)

	if arp.Operation == 1 {
		// ARP Request
		fmt.Printf("ARP Request from %v to %v\n", arp.SourceProtAddress, arp.DstProtAddress)
	} else {
		// ARP Reply
		//fmt.Println("ARP Reply")
	}
}

