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
	// Listez toate layer-urile disponibile pentru acest packet
	layerNames := make([]string, 0)
	for _, layer := range packet.Layers() {
		layerNames = append( layerNames, layer.LayerType().String() )
	}
	fmt.Println( strings.Join( layerNames, " " ))

	if packet.Layer( layers.LayerTypeTCP) != nil {
		handleTCPPacket( packet )
	} else {
		fmt.Println(".")
	}

}

func handleTCPPacket( packet gopacket.Packet ) {
	tcpLayer := packet.Layer( layers.LayerTypeTCP )
	tcp, _ := tcpLayer.(*layers.TCP)

	ipv4Layer := packet.Layer( layers.LayerTypeIPv4 )
	ipv4, _ := ipv4Layer.(*layers.IPv4)
	// fmt.Printf("TCP packet src port %d to destination port %d\n", tcp.SrcPort, tcp.DstPort )
	fmt.Printf("TCP packet from %d:%d to destination %d:%d\n", ipv4.SrcIP, tcp.SrcPort, ipv4.DstIP, tcp.DstPort)
}

