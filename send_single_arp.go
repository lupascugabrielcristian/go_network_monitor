package main

import (
	"fmt"
	"net"
	_"strconv"
	_"strings"

	"github.com/IbrahimShahzad/gonfigure"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	fmt.Println("Reading config file /tmp/go_mon_conf.ini")
	objINI, err := gonfigure.LoadINI("/tmp/go_mon_conf.ini")

	if err != nil {
		panic("Config file not found. Should be /tmp/go_mon_conf.ini")
	}

	// NETWORK INTERFACE
	// Obtin numele din fisierul de configurare
	ntwkInterface, err := gonfigure.GetParameterValue(objINI, "Monitor", "interface")
	if err != nil {
		panic("Config value 'interface' from 'Monitor' section not found")
	}
	// Obtin structura de tip Interface dupa numele citit
	iface, err :=  net.InterfaceByName( ntwkInterface )
	if err != nil {
		panic("Config value 'interface' from 'Monitor' section not found")
	}

	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	// Get handle
	handle, err := pcap.OpenLive(ntwkInterface, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	// Write buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Create ARP request packet
	routerMac, err := net.ParseMAC("38:de:ad:d7:47:90")	// MAC-ul meu

	if err != nil {
		panic( err )
	}

	dst := []byte{ 192, 168, 10, 129 }		// Target IP
	src := []byte{ 192, 168, 10, 154 }		// Sender IP

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   routerMac,
		SourceProtAddress: src,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dst,
	}

	// Completez bufferul cu noul packet
	gopacket.SerializeLayers( buf, opts, &eth, &arp )
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		panic( err )
	}

}
