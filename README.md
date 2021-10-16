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

Start capturing packets on the default interface.

```console
$ pj
```

Start capturing packets on the `en0` interface.

```console
$ pj -interface en0
...
{"eth":{"dst":"ff:ff:ff:ff:ff:ff","src":"00:0b:82:01:fc:42","type":2048},"ipv4":{"checksum":6026,"dst_ip":"255.255.255.255","flags":"","frag_offset":0,"id":43063,"ihl":5,"length":300,"options":[],"padding":null,"protocol":17,"src_ip":"0.0.0.0","tos":0,"ttl":250,"version":4},"metadata":{"device_addresses":"","device_description":"","device_name":"en0","length":314,"packet_number":3,"time":"1969-12-31T19:00:00-05:00","truncated":false},"udp":{"checksum":40893,"dst_port":67,"src_port":68}}
...
```

Read packets from `test.pcapng` file.

```console
$ pj -file test.pcapng
{"eth":{"dst":"ff:ff:ff:ff:ff:ff","src":"00:0b:82:01:fc:42","type":2048},"ipv4":{"checksum":6027,"dst_ip":"255.255.255.255","flags":"","frag_offset":0,"id":43062,"ihl":5,"length":300,"options":[],"padding":null,"protocol":17,"src_ip":"0.0.0.0","tos":0,"ttl":250,"version":4},"metadata":{"device_addresses":"","device_description":"","device_name":"","length":314,"packet_number":1,"time":"1969-12-31T19:00:00-05:00","truncated":false},"udp":{"checksum":22815,"dst_port":67,"src_port":68}}
...
```

Capture packets on the default interface, filtered using `jq` to select packets that have a TCP layer.

```console
$ pj | jq 'select(.tcp)'
...
```

Capture packets on the default interface, filtered using `jq` to select packets that do NOT have a TCP layer (like DNS using UDP).

```console
$ pj | jq 'select(.tcp == null)'
...
```

Capture packets on the default interface, filtered using `jq` to select TCP packets with a destination port of 443 (HTTPS).

```console
$ pj | jq 'select(.tcp.dst_port == 443)'
```

Capture packets on the default interface, filtered using `jq` to select TCP packets with a destination port or source port of 22 (SSH).

```console
$ pj | jq 'select(.tcp.dst_port == 22 or .tcp.src_port == 22)'
```

Capture packets on the default interface, filtered using `jq` to select TCP RST packets.

```console
$ pj | jq 'select(.tcp.rst)'
```

Capture packets on the default interface, filtered using `jq` to select TCP FIN packets.

```console
$ pj | jq 'select(.tcp.fin)'
```

Capture packets on the default interface, filtered using `jq` to select TCP packet that contain an HTTP response.

```console
$ pj | jq 'select(.tcp.payload | startswith("HTTP/1.1"))'
```