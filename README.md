# pj

Command-line application to convert network packets into JSON.

## Installation

```console
$ apt-get install -y libpcap-dev
...
$ go install github.com/picatz/pj@latest
...
```

## Help Menu

```console
$ pj -help
  -interface string
        network interface to listen on (default "<FIRST_NON_LOOPBACK>")
  -file string
        pcap file to read packets from
  -filter string
        apply bpf filter to capture or pcap file
  -list-devs
        list network interfaces
  -promiscuous
        capture in promiscuous mode
```

## Usage

```console
$ pj -file test.pcapng
{"eth":{"dst":"ff:ff:ff:ff:ff:ff","src":"00:0b:82:01:fc:42","type":2048},"ipv4":{"checksum":6027,"dst_ip":"255.255.255.255","flags":"","frag_offset":0,"id":43062,"ihl":5,"length":300,"options":[],"padding":null,"protocol":17,"src_ip":"0.0.0.0","tos":0,"ttl":250,"version":4},"metadata":{"device_addresses":"","device_description":"","device_name":"","length":314,"packet_number":1,"time":"1969-12-31T19:00:00-05:00","truncated":false},"udp":{"checksum":22815,"dst_port":67,"src_port":68}}
...
```

```console
$ pj -interface en0
...
{"eth":{"dst":"ff:ff:ff:ff:ff:ff","src":"00:0b:82:01:fc:42","type":2048},"ipv4":{"checksum":6026,"dst_ip":"255.255.255.255","flags":"","frag_offset":0,"id":43063,"ihl":5,"length":300,"options":[],"padding":null,"protocol":17,"src_ip":"0.0.0.0","tos":0,"ttl":250,"version":4},"metadata":{"device_addresses":"","device_description":"","device_name":"en0","length":314,"packet_number":3,"time":"1969-12-31T19:00:00-05:00","truncated":false},"udp":{"checksum":40893,"dst_port":67,"src_port":68}}
...
```