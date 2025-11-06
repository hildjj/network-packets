# network-packets

Parse information from network packets at layers 2 (Ethernet), 3 (IPv4/IPv6, ARP), and 4 (TCP, UDP, ICMP, ICMP6).

Given a network packet either starting at the Ethernet header or starting at
the IP header, parse the packet and return a structure.

## Installation

```sh
npm install network-packets
```

## API

Full [API documentation](http://hildjj.github.io/network-packets/) is available.

Example:

```js
import {LINKTYPE_ETHERNET, LINKTYPE_RAW, readPacket} from 'network-packets';
const eth = new Uint8Array([/* Ethernet Bytes... */]);
const ethPacket = readPacket(eth, LINKTYPE_ETHERNET);
const ipv6 = new Uint8Array([/* IPv6 Bytes... */]);
const ipv6Packet = readPacket(ipv6, LINKTYPE_RAW);
```

---
[![Tests](https://github.com/hildjj/network-packets/actions/workflows/node.js.yml/badge.svg)](https://github.com/hildjj/network-packets/actions/workflows/node.js.yml)
[![codecov](https://codecov.io/gh/hildjj/network-packets/graph/badge.svg?token=O5EJHMGSOU)](https://codecov.io/gh/hildjj/network-packets)
