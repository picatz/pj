package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshotLen int32 = 65535
	err         error
	packetCount int
)

const hexDigit = "0123456789abcdef"

func hardwareAddrString(a []byte) string {
	if len(a) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(a)*3-1)
	for i, b := range a {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return string(buf)
}

func printBiteSizedJSON(record map[string]interface{}) {
	b, err := json.Marshal(record)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(b))
}

var (
	file        string
	iface       string
	filter      string
	listDevs    bool
	biteSized   bool
	promiscuous bool
	jsonIsEvil  bool
)

func init() {
	// Use the first, non-loopback interface if no interface is given.
	// https://github.com/picatz/iface/blob/master/iface.go#L90
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, ifc := range ifaces {
		// must have mac address, FlagUp and FlagBroadcast
		if ifc.HardwareAddr != nil && ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagBroadcast != 0 {
			iface = ifc.Name
			break
		}
	}

	flag.StringVar(&file, "file", "", "pcap file to read packets from")
	flag.StringVar(&filter, "filter", "", "apply bpf filter to capture or pcap file")
	flag.StringVar(&iface, "interface", iface, "network interface to listen on")
	flag.BoolVar(&listDevs, "list-devs", false, "list network interfaces")
	flag.BoolVar(&jsonIsEvil, "json-is-evil", false, "don't do any of that json stuff")
	flag.BoolVar(&promiscuous, "promiscuous", false, "capture in promiscuous mode")
	// stackdriver has a 100k log entry limit...
	flag.BoolVar(&biteSized, "bite-sized", false, "split packet json information into smaller chunks, spanning multiple lines")
	flag.Parse()

	if listDevs {
		// Find all devices
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
		// Print device information
		fmt.Println("Devices found:")
		for _, device := range devices {
			fmt.Println("\nName: ", device.Name)
			fmt.Println("Description: ", device.Description)
			fmt.Println("Devices addresses: ", device.Description)
			for _, address := range device.Addresses {
				fmt.Println("- IP address: ", address.IP)
				fmt.Println("- Subnet mask: ", address.Netmask)
			}
		}
		os.Exit(0)
	}
}

func main() {

	var (
		pcapHandle *pcap.Handle

		deviceName  string
		deviceDesc  string
		deviceAddrs = []map[string]string{}
	)

	if file != "" {
		pcapHandle, err = pcap.OpenOffline(file)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Find all devices
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		for _, device := range devices {
			if device.Name == iface {
				pcapHandle, err = pcap.OpenLive(device.Name, snapshotLen, promiscuous, pcap.BlockForever)
				if err != nil {
					log.Fatal(err)
				}
				deviceName = device.Name
				deviceDesc = device.Description
				for _, address := range device.Addresses {
					deviceAddrs = append(deviceAddrs, map[string]string{
						"ip_address":  address.IP.String(),
						"subnet_mask": address.Netmask.String(),
					})
				}
			}
		}
	}

	defer pcapHandle.Close()

	if filter != "" {
		err := pcapHandle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}
	}

	if biteSized {
		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
		for packet := range packetSource.Packets() {
			packetCount++
			record := make(map[string]interface{})
			metaData := packet.Metadata()
			record["packet"] = packetCount
			record["time"] = metaData.Timestamp
			record["truncated"] = metaData.Truncated
			record["length"] = metaData.Length
			record["device_name"] = deviceName
			record["device_description"] = deviceDesc
			record["device_addresses"] = deviceAddrs
			printBiteSizedJSON(record)
			for _, layer := range packet.Layers() {
				switch layer.LayerType() {
				case layers.LayerTypeEthernet:
					record := make(map[string]interface{})
					record["packet"] = packetCount
					record["eth"] = true
					eth, _ := layer.(*layers.Ethernet)
					record["src"] = eth.SrcMAC.String()
					record["dst"] = eth.DstMAC.String()
					record["type"] = eth.EthernetType
					printBiteSizedJSON(record)
				case layers.LayerTypeIPv4:
					record := make(map[string]interface{})
					record["packet"] = packetCount
					record["ip"] = true
					ipv4, _ := layer.(*layers.IPv4)
					record["version"] = ipv4.Version
					record["ihl"] = ipv4.IHL
					record["tos"] = ipv4.TOS
					record["length"] = ipv4.Length
					record["id"] = ipv4.Id
					record["flags"] = ipv4.Flags.String()
					record["frag_offset"] = ipv4.FragOffset
					record["ttl"] = ipv4.TTL
					record["protocol"] = ipv4.Protocol
					record["checksum"] = ipv4.Checksum
					record["src_ip"] = ipv4.SrcIP.String()
					record["dst_ip"] = ipv4.DstIP.String()
					options := []string{}
					for _, option := range ipv4.Options {
						options = append(options, option.String())
					}
					record["options"] = options
					record["padding"] = ipv4.Padding
					printBiteSizedJSON(record)
				case layers.LayerTypeTCP:
					record := make(map[string]interface{})
					record["packet"] = packetCount
					record["tcp"] = true
					tcp, _ := layer.(*layers.TCP)
					record["src_port"] = tcp.SrcPort
					record["dst_port"] = tcp.DstPort
					record["seq"] = tcp.Seq
					record["ack"] = tcp.Ack
					record["data_offset"] = tcp.DataOffset
					record["fin"] = tcp.FIN
					record["syn"] = tcp.SYN
					record["rst"] = tcp.RST
					record["psh"] = tcp.PSH
					record["ack"] = tcp.ACK
					record["urg"] = tcp.URG
					record["ece"] = tcp.ECE
					record["cwr"] = tcp.CWR
					record["ns"] = tcp.NS
					options := []string{}
					for _, option := range tcp.Options {
						options = append(options, option.String())
					}
					record["options"] = options
					record["padding"] = tcp.Padding
					record["payload"] = string(tcp.Payload)
					record["payload_length"] = len(tcp.Payload)
					printBiteSizedJSON(record)
				case layers.LayerTypeUDP:
					record := make(map[string]interface{})
					record["packet"] = packetCount
					record["udp"] = true
					udp, _ := layer.(*layers.UDP)
					record["src_port"] = udp.SrcPort
					record["dst_port"] = udp.DstPort
					record["checksum"] = udp.Checksum
					record["payload"] = string(udp.Payload)
					record["payload_length"] = len(udp.Payload)
					printBiteSizedJSON(record)
				case layers.LayerTypeICMPv4:
					record := make(map[string]interface{})
					record["packet"] = packetCount
					record["icmp"] = true
					icmpv4, _ := layer.(*layers.ICMPv4)
					record["type_code"] = icmpv4.TypeCode.String()
					record["checksum"] = icmpv4.Checksum
					record["id"] = icmpv4.Id
					record["seq"] = icmpv4.Seq
					record["payload"] = string(icmpv4.Payload)
					printBiteSizedJSON(record)
				case layers.LayerTypeARP:
					record := make(map[string]interface{})
					record["packet"] = packetCount
					record["arp"] = true
					arp, _ := layer.(*layers.ARP)
					record["addr_type"] = arp.AddrType
					record["protocol"] = arp.Protocol
					record["hw_address_size"] = arp.HwAddressSize
					record["prot_address_size"] = arp.ProtAddressSize
					record["operation"] = arp.Operation
					record["source_hw_address"] = hardwareAddrString(arp.SourceHwAddress)
					record["source_prot_address"] = net.IP(arp.SourceProtAddress).String()
					record["dst_hw_address"] = hardwareAddrString(arp.DstHwAddress)
					record["dst_prot_address"] = net.IP(arp.DstProtAddress).String()
					record["payload"] = string(arp.Payload)
					printBiteSizedJSON(record)
				case layers.LayerTypeDNS:
					record := make(map[string]interface{})
					record["packet"] = packetCount
					record["dns"] = true
					dns, _ := layer.(*layers.DNS)
					record["id"] = dns.ID
					record["qr"] = dns.QR
					record["op_code"] = dns.OpCode
					record["aa"] = dns.AA
					record["tc"] = dns.TC
					record["rd"] = dns.RD
					record["ra"] = dns.RA
					record["z"] = dns.Z
					record["response_code"] = dns.ResponseCode.String()
					record["qd_count"] = dns.QDCount
					record["an_count"] = dns.ANCount
					record["ns_count"] = dns.NSCount
					record["ar_count"] = dns.ARCount

					questions := []map[string]interface{}{}
					for _, q := range dns.Questions {
						question := map[string]interface{}{}
						question["name"] = string(q.Name)
						question["type"] = q.Type.String()
						question["class"] = q.Class.String()
						questions = append(questions, question)
					}
					record["questions"] = questions

					answers := []string{}
					for _, a := range dns.Answers {
						answers = append(answers, a.String())
					}
					record["answers"] = answers

					authorities := []string{}
					for _, a := range dns.Authorities {
						authorities = append(authorities, a.String())
					}
					record["authorities"] = authorities

					additionals := []string{}
					for _, a := range dns.Additionals {
						additionals = append(additionals, a.String())
					}
					record["additionals"] = additionals

					printBiteSizedJSON(record)
				}
			}

			b, err := json.Marshal(record)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(string(b))
		}
	} else if jsonIsEvil {
		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Println(packet)
		}
	} else {
		// Use the handle as a packet source to process all packets
		packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
		for packet := range packetSource.Packets() {
			packetCount++
			record := make(map[string]map[string]interface{})
			record["metadata"] = map[string]interface{}{}
			metaData := packet.Metadata()
			record["metadata"]["packet_number"] = packetCount
			record["metadata"]["time"] = metaData.Timestamp
			record["metadata"]["truncated"] = metaData.Truncated
			record["metadata"]["length"] = metaData.Length
			record["metadata"]["device_name"] = deviceName
			record["metadata"]["device_description"] = deviceDesc
			record["metadata"]["device_addresses"] = deviceName
			for _, layer := range packet.Layers() {
				switch layer.LayerType() {
				case layers.LayerTypeEthernet:
					eth, _ := layer.(*layers.Ethernet)
					record["eth"] = make(map[string]interface{})
					record["eth"]["src"] = eth.SrcMAC.String()
					record["eth"]["dst"] = eth.DstMAC.String()
					record["eth"]["type"] = eth.EthernetType
				case layers.LayerTypeIPv4:
					ipv4, _ := layer.(*layers.IPv4)
					record["ipv4"] = make(map[string]interface{})
					record["ipv4"]["version"] = ipv4.Version
					record["ipv4"]["ihl"] = ipv4.IHL
					record["ipv4"]["tos"] = ipv4.TOS
					record["ipv4"]["length"] = ipv4.Length
					record["ipv4"]["id"] = ipv4.Id
					record["ipv4"]["flags"] = ipv4.Flags.String()
					record["ipv4"]["frag_offset"] = ipv4.FragOffset
					record["ipv4"]["ttl"] = ipv4.TTL
					record["ipv4"]["protocol"] = ipv4.Protocol
					record["ipv4"]["checksum"] = ipv4.Checksum
					record["ipv4"]["src_ip"] = ipv4.SrcIP.String()
					record["ipv4"]["dst_ip"] = ipv4.DstIP.String()
					options := []string{}
					for _, option := range ipv4.Options {
						options = append(options, option.String())
					}
					record["ipv4"]["options"] = options
					record["ipv4"]["padding"] = ipv4.Padding
				case layers.LayerTypeTCP:
					tcp, _ := layer.(*layers.TCP)
					record["tcp"] = make(map[string]interface{})
					record["tcp"]["src_port"] = tcp.SrcPort
					record["tcp"]["dst_port"] = tcp.DstPort
					record["tcp"]["seq"] = tcp.Seq
					record["tcp"]["ack"] = tcp.Ack
					record["tcp"]["data_offset"] = tcp.DataOffset
					record["tcp"]["fin"] = tcp.FIN
					record["tcp"]["syn"] = tcp.SYN
					record["tcp"]["rst"] = tcp.RST
					record["tcp"]["psh"] = tcp.PSH
					record["tcp"]["ack"] = tcp.ACK
					record["tcp"]["urg"] = tcp.URG
					record["tcp"]["ece"] = tcp.ECE
					record["tcp"]["cwr"] = tcp.CWR
					record["tcp"]["ns"] = tcp.NS
					options := []string{}
					for _, option := range tcp.Options {
						options = append(options, option.String())
					}
					record["tcp"]["options"] = options
					record["tcp"]["padding"] = tcp.Padding
					record["tcp"]["payload"] = string(tcp.Payload)
					record["tcp"]["payload_length"] = len(tcp.Payload)
				case layers.LayerTypeUDP:
					udp, _ := layer.(*layers.UDP)
					record["udp"] = make(map[string]interface{})
					record["udp"]["src_port"] = udp.SrcPort
					record["udp"]["dst_port"] = udp.DstPort
					record["udp"]["checksum"] = udp.Checksum
					record["udp"]["payload"] = string(udp.Payload)
					record["udp"]["payload_length"] = len(udp.Payload)
				case layers.LayerTypeICMPv4:
					icmpv4, _ := layer.(*layers.ICMPv4)
					record["icmpv4"] = make(map[string]interface{})
					record["icmpv4"]["type_code"] = icmpv4.TypeCode.String()
					record["icmpv4"]["checksum"] = icmpv4.Checksum
					record["icmpv4"]["id"] = icmpv4.Id
					record["icmpv4"]["seq"] = icmpv4.Seq
					record["icmpv4"]["payload"] = string(icmpv4.Payload)
				case layers.LayerTypeARP:
					arp, _ := layer.(*layers.ARP)
					record["arp"] = make(map[string]interface{})
					record["arp"]["addr_type"] = arp.AddrType
					record["arp"]["protocol"] = arp.Protocol
					record["arp"]["hw_address_size"] = arp.HwAddressSize
					record["arp"]["prot_address_size"] = arp.ProtAddressSize
					record["arp"]["operation"] = arp.Operation
					record["arp"]["source_hw_address"] = hardwareAddrString(arp.SourceHwAddress)
					record["arp"]["source_prot_address"] = net.IP(arp.SourceProtAddress).String()
					record["arp"]["dst_hw_address"] = hardwareAddrString(arp.DstHwAddress)
					record["arp"]["dst_prot_address"] = net.IP(arp.DstProtAddress).String()
					record["arp"]["payload"] = string(arp.Payload)
				case layers.LayerTypeDNS:
					dns, _ := layer.(*layers.DNS)
					record["dns"] = make(map[string]interface{})
					record["dns"]["id"] = dns.ID
					record["dns"]["qr"] = dns.QR
					record["dns"]["op_code"] = dns.OpCode
					record["dns"]["authoritative_answer"] = dns.AA
					record["dns"]["truncated"] = dns.TC
					record["dns"]["recursion_desired"] = dns.RD
					record["dns"]["recursion_available"] = dns.RA
					record["dns"]["z"] = dns.Z
					record["dns"]["response_code"] = dns.ResponseCode.String()
					record["dns"]["qd_count"] = dns.QDCount
					record["dns"]["an_count"] = dns.ANCount
					record["dns"]["ns_count"] = dns.NSCount
					record["dns"]["ar_count"] = dns.ARCount

					questions := []map[string]interface{}{}
					for _, q := range dns.Questions {
						question := map[string]interface{}{}
						question["name"] = string(q.Name)
						question["type"] = q.Type.String()
						question["class"] = q.Class.String()
						questions = append(questions, question)
					}
					record["dns"]["questions"] = questions

					answers := []string{}
					for _, a := range dns.Answers {
						answers = append(answers, a.String())
					}
					record["dns"]["answers"] = answers

					authorities := []string{}
					for _, a := range dns.Authorities {
						authorities = append(authorities, a.String())
					}
					record["dns"]["authorities"] = authorities

					additionals := []string{}
					for _, a := range dns.Additionals {
						additionals = append(additionals, a.String())
					}
					record["dns"]["additionals"] = additionals
				}
			}

			b, err := json.Marshal(record)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println(string(b))
		}
	}

}
