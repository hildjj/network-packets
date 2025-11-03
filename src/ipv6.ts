import {DataViewReader, Packet} from 'dataview-stream';
import {type L4, L4_DECODERS, L4_PROTOCOLS, type TruncatedL4} from './L4.ts';
import type {PartialTyped, Pretty} from './types.ts';
import {decode as ipDecode} from '@leichtgewicht/ip-codec';

export const IPV6_ETHERTYPE = 0x86dd;

const IPV6_EXTENSIONS = new Set([
  0, 43, 44, 50, 51, 60, 135, 139, 140, 253, 254,
]);

export interface IPv6 {
  type: 'ipv6';
  version: number;
  class: number;
  flow: number;
  length: number;
  protocol: string | number;
  hopLimit: number;
  src: string;
  dest: string;
  data: L4;
}
export type TruncatedIPv6 = Pretty<Omit<PartialTyped<IPv6>, 'data'> & {
  data?: TruncatedL4;
}>;

interface IPv6temp {
  vtf: number;
  next: number;
}

/**
 * Read an IPv6 packet.
 *
 * @param r Reader.
 * @returns Parsed packet.
 */
export function readIPv6(r: DataViewReader): IPv6 {
  // TODO: Jumbo payloads
  const p = new Packet<IPv6, IPv6temp>(r);
  p.constant('type', 'ipv6')
    .u32('vtf', {temp: true})
    .bits({fromTemp: 'vtf', to: 'version', start: 31, finish: 28})
    .bits({fromTemp: 'vtf', to: 'class', start: 27, finish: 20})
    .bits({fromTemp: 'vtf', to: 'flow', start: 19, finish: 0})
    .u16('length')
    .u8('next', {temp: true})
    .u8('hopLimit')
    .bytes('src', 16, {convert: v => ipDecode(v)})
    .bytes('dest', 16, {convert: v => ipDecode(v)});

  let decoder: undefined | ((r: DataViewReader) => L4) = undefined;
  let {next} = p.temp;
  while (true) {
    if (next === 59) { // No Next Header
      break;
    }
    decoder = L4_DECODERS.get(next);
    if (decoder) {
      break;
    }
    if (IPV6_EXTENSIONS.has(next)) {
      next = r.u8();
      // Length of this header in 8-octet units, not including the first 8
      // octets; this includes 1 byte for next and one byte for length.
      const extLen = r.u8();
      r.bytes((8 * (extLen + 1)) - 2);
    } else {
      break;
    }
  }
  p.packet.protocol = L4_PROTOCOLS.get(next) ?? next;
  p.packet.data = decoder ? decoder(r) : r.unused();
  return p.packet;
}

/**
 * Read a truncated packet, for example, in an ICMP message.
 *
 * @param r Reader, which will have truncation enabled as a side-effect.
 * @returns Potentially-truncated packet.
 */
export function readIPv6Truncated(r: DataViewReader): TruncatedIPv6 {
  r.allowTruncation = true;
  return readIPv6(r);
}
