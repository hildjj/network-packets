import {DataViewReader, Packet} from 'dataview-stream/packet';
import {type TruncatedIPv6, readIPv6Truncated} from './ipv6.ts';
import {decode as ipDecode} from '@leichtgewicht/ip-codec';

export const ICMP6_PROTO = 58;

const ICMP6_MESSAGE_TYPES = new Map<number, string>([
  [0, 'Reserved 0'],
  [1, 'Destination Unreachable'],
  [2, 'Packet Too Big'],
  [3, 'Time Exceeded'],
  [4, 'Parameter Problem'],
  [100, 'Private experimentation'],
  [101, 'Private experimentation'],
  [127, 'Reserved for expansion of ICMPv6 error messages'],
  [128, 'Echo Request'],
  [129, 'Echo Reply'],
  [130, 'Multicast Listener Query'],
  [131, 'Multicast Listener Report'],
  [132, 'Multicast Listener Done'],
  [133, 'Router Solicitation'],
  [134, 'Router Advertisement'],
  [135, 'Neighbor Solicitation'],
  [136, 'Neighbor Advertisement'],
  [137, 'Redirect Message'],
  [138, 'Router Renumbering'],
  [139, 'ICMP Node Information Query'],
  [140, 'ICMP Node Information Response'],
  [141, 'Inverse Neighbor Discovery Solicitation Message'],
  [142, 'Inverse Neighbor Discovery Advertisement Message'],
  [143, 'Version 2 Multicast Listener Report'],
  [144, 'Home Agent Address Discovery Request Message'],
  [145, 'Home Agent Address Discovery Reply Message'],
  [146, 'Mobile Prefix Solicitation'],
  [147, 'Mobile Prefix Advertisement'],
  [148, 'Certification Path Solicitation Message'],
  [149, 'Certification Path Advertisement Message'],
  [150, 'ICMP messages utilized by experimental mobility protocols such as Seamoby'],
  [151, 'Multicast Router Advertisement'],
  [152, 'Multicast Router Solicitation'],
  [153, 'Multicast Router Termination'],
  [154, 'FMIPv6 Messages'],
  [155, 'RPL Control Message'],
  [156, 'ILNPv6 Locator Update Message'],
  [157, 'Duplicate Address Request'],
  [158, 'Duplicate Address Confirmation'],
  [159, 'MPL Control Message'],
  [160, 'Extended Echo Request'],
  [161, 'Extended Echo Reply'],
  [200, 'Private experimentation'],
  [201, 'Private experimentation'],
  [255, '"Reserved for expansion of ICMPv6 informational messages'],
]);

const ICMP6_CODE_MAPS = new Map<number, Map<number, string>>([
  [1, new Map([
    [0, 'no route to destination'],
    [1, 'communication with destination administratively prohibited'],
    [2, 'beyond scope of source address'],
    [3, 'address unreachable'],
    [4, 'port unreachable'],
    [5, 'source address failed ingress/egress policy'],
    [6, 'reject route to destination'],
    [7, 'Error in Source Routing Header'],
    [8, 'Headers too long'],
    [9, 'Error in P-Route'],
  ])],
  [3, new Map([
    [0, 'hop limit exceeded in transit'],
    [1, 'fragment reassembly time exceeded'],
  ])],
  [4, new Map([
    [0, 'erroneous header field encountered'],
    [1, 'unrecognized Next Header type encountered'],
    [2, 'unrecognized IPv6 option encountered'],
    [3, 'IPv6 First Fragment has incomplete IPv6 Header Chain'],
    [4, 'SR Upper-layer Header Error'],
    [5, 'Unrecognized Next Header type encountered by intermediate node'],
    [6, 'Extension header too big'],
    [7, 'Extension header chain too long'],
    [8, 'Too many extension headers'],
    [9, 'Too many options in extension header'],
    [10, 'Option too big'],
  ])],
  [138, new Map([
    [0, 'Router Renumbering Command'],
    [1, 'Router Renumbering Result'],
    [255, 'Sequence Number Reset'],
  ])],
  [139, new Map([
    [0, 'The Data field contains an IPv6 address which is the Subject of this Query.'],
    [1, 'The Data field contains a name which is the Subject of this Query, or is empty, as in the case of a NOOP.'],
    [2, 'The Data field contains an IPv4 address which is the Subject of this Query.'],
  ])],
  [140, new Map([
    [0, 'A successful reply. The Reply Data field may or may not be empty.'],
    [1, 'The Responder refuses to supply the answer. The Reply Data field will be empty.'],
    [2, 'The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty.'],
  ])],
  [157, new Map([
    [0, 'DAR message'],
    [1, 'EDAR message with 64-bit ROVR field'],
    [2, 'EDAR message with 128-bit ROVR field'],
    [3, 'EDAR message with 192-bit ROVR field'],
    [4, 'EDAR message with 256-bit ROVR field'],
  ])],
  [158, new Map([
    [0, 'DAC message'],
    [1, 'EDAC message with 64-bit ROVR field'],
    [2, 'EDAC message with 128-bit ROVR field'],
    [3, 'EDAC message with 192-bit ROVR field'],
    [4, 'EDAC message with 256-bit ROVR field'],
  ])],
  [160, new Map([
    [0, 'No Error'],
  ])],
  [161, new Map([
    [0, 'No Error'],
    [1, 'Malformed Query'],
    [2, 'No Such Interface'],
    [3, 'No Such Table Entry'],
    [4, 'Multiple Interfaces Satisfy Query'],
  ])],
]);

const ND_OPTIONS = new Map<number, string>([
  [1, 'Source Link-layer Address'],
  [2, 'Target Link-layer Address'],
  [3, 'Prefix Information'],
  [4, 'Redirected Header'],
  [5, 'MTU'],
  [6, 'NBMA Shortcut Limit Option'],
  [7, 'Advertisement Interval Option'],
  [8, 'Home Agent Information Option'],
  [9, 'Source Address List'],
  [10, 'Target Address List'],
  [11, 'CGA option'],
  [12, 'RSA Signature option'],
  [13, 'Timestamp option'],
  [14, 'Nonce option'],
  [15, 'Trust Anchor option'],
  [16, 'Certificate option'],
  [17, 'IP Address/Prefix Option'],
  [18, 'New Router Prefix Information Option'],
  [19, 'Link-layer Address Option'],
  [20, 'Neighbor Advertisement Acknowledgment Option'],
  [21, 'PvD ID Router Advertisement Option'],
  [23, 'MAP Option'],
  [24, 'Route Information Option'],
  [25, 'Recursive DNS Server Option'],
  [26, 'RA Flags Extension Option'],
  [27, 'Handover Key Request Option'],
  [28, 'Handover Key Reply Option'],
  [29, 'Handover Assist Information Option'],
  [30, 'Mobile Node Identifier Option'],
  [31, 'DNS Search List Option'],
  [32, 'Proxy Signature (PS)'],
  [33, 'Address Registration Option'],
  [34, '6LoWPAN Context Option'],
  [35, 'Authoritative Border Router Option'],
  [36, '6LoWPAN Capability Indication Option (6CIO)'],
  [37, 'DHCP Captive-Portal'],
  [38, 'PREF64 option'],
  [39, 'Crypto-ID Parameters Option (CIPO)'],
  [40, 'NDP Signature Option (NDPSO)'],
  [41, 'Resource Directory Address Option'],
  [42, 'Consistent Uptime Option'],
  [138, 'CARD Request option'],
  [139, 'CARD Reply option'],
  [144, 'Encrypted DNS Option'],
  [253, 'RFC3692-style Experiment 1'],
  [254, 'RFC3692-style Experiment 2'],
]);

function codeToText(code: number, type: number): string | number {
  return ICMP6_CODE_MAPS.get(type)?.get(code) ?? code;
}

export interface NeighborDiscoveryOption {
  type: string | number;
  length: number;
  data: Uint8Array;
}

export interface NeighborSolicitation {
  type: 'NeighborSolicitation';
  target: string;
  options: NeighborDiscoveryOption[];
}

interface NeighborSolicitationTemp {
  reserved: number;
}

function readNDoption(r: DataViewReader): NeighborDiscoveryOption {
  const p = new Packet<NeighborDiscoveryOption>(r);
  return p.u8('type', {convert: v => ND_OPTIONS.get(v) ?? v})
    .u8('length', {convert: v => v * 8})
    .bytes('data', p.packet.length - 2)
    .packet;
}

function readNeighborSolicitation(r: DataViewReader): NeighborSolicitation {
  const p = new Packet<NeighborSolicitation, NeighborSolicitationTemp>(r);
  return p.constant('type', 'NeighborSolicitation')
    .skip(4)
    .bytes('target', 16, {convert: v => ipDecode(v)})
    .while('options', () => r.offset < r.original.length, () => readNDoption(r))
    .packet;
}

export interface NeighborAdvertisement {
  type: 'NeighborAdvertisement';
  flags: Set<'R' | 'S' | 'O'>;
  target: string;
}

interface NeighborAdvertisementTemp {
  reserved: number;
}

function readNeighborAdvertisement(r: DataViewReader): NeighborAdvertisement {
  const p = new Packet<NeighborAdvertisement, NeighborAdvertisementTemp>(r);
  return p.constant('type', 'NeighborAdvertisement')
    .u16('reserved', {temp: true})
    .bits({fromTemp: 'reserved', to: 'flags', set: {R: 15, S: 14, O: 13}})
    .bytes('target', 16, {convert: v => ipDecode(v)})
    .packet;
}

export interface IPv6withLength {
  type: 'IPv6Len';
  originalLength: number;
  ipv6: TruncatedIPv6;
}

function readLengthIPv6(r: DataViewReader): IPv6withLength {
  const p = new Packet<IPv6withLength>(r);
  p.constant('type', 'IPv6Len')
    .u8('originalLength')
    .skip(3);
  p.packet.ipv6 = readIPv6Truncated(r);
  return p.packet;
}

export interface MTUandIPv6 {
  type: 'IPv6MTU';
  MTU: number;
  ipv6: TruncatedIPv6;
}

function readMTUipV6(r: DataViewReader): MTUandIPv6 {
  const p = new Packet<MTUandIPv6>(r);
  p.constant('type', 'IPv6MTU')
    .skip(4)
    .u32('MTU');
  p.packet.ipv6 = readIPv6Truncated(r);
  return p.packet;
}

export interface PointerAndIPv6 {
  type: 'IPv6Pointer';
  pointer: number;
  ipv6: TruncatedIPv6;
}

function readPointerIpv6(r: DataViewReader): PointerAndIPv6 {
  const p = new Packet<PointerAndIPv6>(r);
  p.constant('type', 'IPv6Pointer')
    .u32('pointer');
  p.packet.ipv6 = readIPv6Truncated(r);
  return p.packet;
}

export interface Echo {
  type: 'echo';
  id: number;
  seq: number;
  data: Uint8Array;
}

function readEcho(r: DataViewReader): Echo {
  const p = new Packet<Echo>(r);
  p.constant('type', 'echo')
    .u16('id')
    .u16('seq')
    .unused('data');
  return p.packet;
}

export type ICMP6_MESSAGE =
  NeighborSolicitation |
  NeighborAdvertisement |
  IPv6withLength |
  MTUandIPv6 |
  PointerAndIPv6 |
  Echo |
  Uint8Array;

const ICMP6_MESSAGE_DECODER =
  new Map<number, (r: DataViewReader) => ICMP6_MESSAGE>([
    [1, readLengthIPv6], // Destination Unreachable
    [2, readMTUipV6], // Packet Too Big
    [3, readLengthIPv6], // Time Exceeded
    [4, readPointerIpv6], // Parameter Problem
    [128, readEcho], // Echo Request
    [129, readEcho], // Echo Request
    [135, readNeighborSolicitation],
    [136, readNeighborAdvertisement],
  ]);

export interface ICMP6 {
  type: 'icmpipv6_icmp';
  messageType: number | string;
  error: boolean;
  code: string | number;
  checksum: number;
  originalLength?: number;
  data: ICMP6_MESSAGE;
}

interface ICMP6temp {
  mtype: number;
}

/**
 * Read an ICMP6 packet.
 *
 * @param r Reader.
 * @returns Parsed packet.
 * @see https://www.rfc-editor.org/rfc/rfc4443.html
 * @see https://www.rfc-editor.org/rfc/rfc4884.html
 * @see https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
 */
export function readICMP6(r: DataViewReader): ICMP6 {
  const p = new Packet<ICMP6, ICMP6temp>(r);
  p.constant('type', 'ipv6_icmp')
    .u8('mtype', {temp: true})
    .bits({
      fromTemp: 'mtype',
      to: 'messageType',
      start: 7,
      finish: 0,
      convert: v => ICMP6_MESSAGE_TYPES.get(v as number) ?? v,
    })
    .bits({fromTemp: 'mtype', to: 'error', start: 7})
    .u8('code', {convert: v => codeToText(v, p.temp.mtype)})
    .u16('checksum');
  const decoder = ICMP6_MESSAGE_DECODER.get(p.temp.mtype);
  p.packet.data = decoder ? decoder(r) : r.unused();
  return p.packet;
}
