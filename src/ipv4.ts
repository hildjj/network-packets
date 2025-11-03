import {DataViewReader, Packet} from 'dataview-stream';
import {type L4, L4_DECODERS, L4_PROTOCOLS, TruncatedL4} from './L4.ts';
import type {PartialTyped, Pretty} from './types.ts';
import {decode as ipDecode} from '@leichtgewicht/ip-codec';

export const IPV4_ETHERTYPE = 0x0800;
export type IPv4flags = 'R' | 'DF' | 'MF';

export interface IPv4 {
  type: 'ipv4';
  version: number;
  IHL: number;
  DSCP: number;
  ECN: number;
  length: number;
  id: number;
  flags: Set<IPv4flags>;
  frag_offset: number;
  ttl: number;
  protocol: number | string;
  checksum: number;
  src: string;
  dest: string;
  opts: number[];
  data: L4;
}

export type TruncatedIPv4 = Pretty<Omit<PartialTyped<IPv4>, 'data'> & {
  data?: TruncatedL4;
}>;

interface IPv4temp {
  vIHL: number;
  dscpECN: number;
  ff: number;
  protocol: number;
}

/**
 * Read an IPv4 packet.
 *
 * @param r Reader.
 * @returns Parsed packet.
 */
export function readIPv4(r: DataViewReader): IPv4 {
  const p = new Packet<IPv4, IPv4temp>(r);
  p.constant('type', 'ipv4')
    .u8('vIHL', {temp: true})
    .bits({fromTemp: 'vIHL', to: 'version', start: 7, finish: 4})
    .bits({fromTemp: 'vIHL', to: 'IHL', start: 4, finish: 0})
    .u8('dscpECN', {temp: true})
    .bits({fromTemp: 'dscpECN', to: 'DSCP', start: 7, finish: 2})
    .bits({fromTemp: 'dscpECN', to: 'ECN', start: 1, finish: 0})
    .u16('length')
    .u16('id')
    .u16('ff', {temp: true})
    .bits({fromTemp: 'ff', to: 'flags', set: {R: 15, DF: 14, MF: 13}})
    .bits({fromTemp: 'ff', to: 'frag_offset', start: 12, finish: 0})
    .u8('ttl')
    .u8('protocol', {temp: true})
    .u16('checksum')
    .bytes('src', 4, {convert: v => ipDecode(v)})
    .bytes('dest', 4, {convert: v => ipDecode(v)})
    .times('opts', p.packet.IHL - 5, () => r.u32());

  const {protocol} = p.temp;
  p.packet.protocol = L4_PROTOCOLS.get(protocol) ?? protocol;
  const decoder = L4_DECODERS.get(protocol);
  p.packet.data = decoder ? decoder(r) : r.unused();
  return p.packet;
}

/**
 * Read a truncated packet, for example, in an ICMP message.
 *
 * @param r Reader, which will have truncation enabled as a side-effect.
 * @returns Potentially-truncated packet.
 */
export function readIPv4Truncated(r: DataViewReader): TruncatedIPv4 {
  r.allowTruncation = true;
  return readIPv4(r);
}
