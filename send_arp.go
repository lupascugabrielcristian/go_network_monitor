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

	// Obtin range-ul de ip-uri pentru requesturile ARP
	fromStr, _ := gonfigure.GetParameterValue(objINI, "ARP_Send", "from")
	from, err := strconv.Atoi(fromStr)
	if err != nil {
		panic("Config value 'from' from 'ARP_Send' section not found")
	}

	toStr, _ := gonfigure.GetParameterValue(objINI, "ARP_Send", "to")
	to, err := strconv.Atoi(toStr)
	if err != nil {
		panic("Config value 'to' from 'ARP_Send' section not found")
	}

	secondByteStr, _ := gonfigure.GetParameterValue(objINI, "ARP_Send", "second_byte")
	secondByte, err := strconv.Atoi(secondByteStr)
	if err != nil {
		panic("Config value 'second_byte' from 'ARP_Send' section not found")
	}

	senderIp, err := gonfigure.GetParameterValue(objINI, "ARP_Send", "sender_ip")
	if err != nil {
		panic("Config value 'sender_ip' from 'ARP_Send' section not found")
	}

	senderMAC, err := gonfigure.GetParameterValue(objINI, "ARP_Send", "sender_mac")
	if err != nil {
		panic("Config value 'sender_mac' from 'ARP_Send' section not found")
	}

	fmt.Println("Sender IP", senderIp)
	fmt.Println("Sender MAC ", senderMAC)

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

	// Obtin range-ul de ip-uri la care vreau sa trimit ARP request
	targetIPs := getTargets(byte(from), byte(to), byte(secondByte))
	for _, targetIp := range targetIPs {

		// Create ARP request packet
		routerMac, err := net.ParseMAC( senderMAC )	// MAC-ul meu

		if err != nil {
			panic( err )
		}

		// Sender IP
		senderBytes := strings.Split(senderIp, ".")
		toIPByte := func( part string ) byte {
			val, err := strconv.Atoi(part)
			if err != nil {
				return 1
			} else {
				return byte(val)
			}
		}
		src := []byte{ 192, 168, toIPByte(senderBytes[2]), toIPByte(senderBytes[3]) }
		fmt.Println(src)

		arp := layers.ARP{
			AddrType:          layers.LinkTypeEthernet,
			Protocol:          layers.EthernetTypeIPv4,
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         layers.ARPRequest,
			SourceHwAddress:   routerMac,
			SourceProtAddress: src,
			DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
			DstProtAddress:    targetIp,
		}

		// Completez bufferul cu noul packet
		gopacket.SerializeLayers( buf, opts, &eth, &arp )
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			panic( err )
		}
	}

}

// from si to sunt limitele ultimului byte din IP
// Genereaza IP-uri de tipul 192.168.10.x unde x este intre from si to, inclusiv
func getTargets(from byte, to byte, secondByte byte) []net.IP {
	// Fac lista goala de ip-uri
	res := make([]net.IP, to - from + 1)

	// Populez fiecare pozitie
	for i := range res {
		res[i] = []byte{ 192, 168, secondByte, from + byte(i) }
	}

	return res
}
