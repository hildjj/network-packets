import type {
  Echo,
  ICMP6,
  ICMP6_MESSAGE,
  IPv6withLength,
  MTUandIPv6,
  NeighborAdvertisement,
  NeighborDiscoveryOption,
  NeighborSolicitation,
  PointerAndIPv6,
} from './icmp6.ts';
import {type Ethernet, readEthernet} from './ethernet.ts';
import {type IPv4, type IPv4flags, type TruncatedIPv4, readIPv4} from './ipv4.ts';
import {type IPv6, type TruncatedIPv6, readIPv6} from './ipv6.ts';
import type {L4, TruncatedL4} from './L4.ts';
import type {PartialTyped, Pretty, Typed} from './types.ts';
import type {TCP, TCPflag} from './tcp.ts';
import type {ARP} from './arp.ts';
import {DataViewReader} from 'dataview-stream';
import type {ICMP} from './icmp.ts';
import type {L3} from './L3.ts';
import type {UDP} from './udp.ts';

export type {
  ARP,
  Echo,
  Ethernet,
  ICMP,
  ICMP6,
  ICMP6_MESSAGE,
  IPv4,
  IPv4flags,
  IPv6,
  IPv6withLength,
  L3,
  L4,
  MTUandIPv6,
  NeighborAdvertisement,
  NeighborDiscoveryOption,
  NeighborSolicitation,
  PartialTyped,
  PointerAndIPv6,
  Pretty,
  TCP,
  TCPflag,
  TruncatedIPv4,
  TruncatedL4,
  TruncatedIPv6,
  Typed,
  UDP,
};

// See https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html
export const LINKTYPE_NULL = 0;
export const LINKTYPE_ETHERNET = 1;
export const LINKTYPE_RAW = 101;

function readIP(r: DataViewReader, ver: number): IPv4 | IPv6 {
  switch (ver) {
    case 4:
      return readIPv4(r);
    case 6:
      return readIPv6(r);
    default:
      throw new Error(`Unsupported IP version: ${ver}`);
  }
}

/**
 * Read an Ethernet packet from the given bytes.
 *
 * @param bytes Full packet.
 * @param linkType The PCAP Link-Layer Type.
 * @returns Ethernet structure.
 * @throws {Error} On invalid linkType, invalid IP version.
 * @see https://www.ietf.org/archive/id/draft-ietf-opsawg-pcaplinktype-13.html#name-initial-values
 */
export function readPacket(
  bytes: Uint8Array,
  linkType = 1
): Ethernet | IPv4 | IPv6 {
  if (bytes.length < 1) {
    throw new Error('Invalid bytes');
  }
  const r = new DataViewReader(bytes);
  switch (linkType) {
    case LINKTYPE_NULL:
      // The first 4 bytes are a type indicator, but it's in host byte
      // order, and I don't want to have to pass that in.  Since we don't
      // support OSI or IPX, we can just skip right to the payload to find
      // out the IP version type.
      r.u32();
      return readIP(r, bytes[4] >> 4);
    case LINKTYPE_ETHERNET:
      return readEthernet(r);
    case LINKTYPE_RAW: {
      return readIP(r, bytes[0] >> 4);
    }
    default:
      throw new Error(`Unsupported linkType: ${linkType}`);
  }
}
