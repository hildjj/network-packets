import {DataViewReader, Packet} from 'dataview-stream';
import {type TruncatedIPv4, readIPv4Truncated} from './ipv4.ts';
import {decode as ipDecode} from '@leichtgewicht/ip-codec';

export const ICMP_PROTO = 1;

const ICMP_TYPES = new Map([
  [0, 'Echo Reply'],
  [1, 'Unassigned'],
  [2, 'Unassigned'],
  [3, 'Destination Unreachable'],
  [4, 'Source Quench'],
  [5, 'Redirect'],
  [6, 'Alternate Host Address'],
  [7, 'Unassigned'],
  [8, 'Echo'],
  [9, 'Router Advertisement'],
  [10, 'Router Solicitation'],
  [11, 'Time Exceeded'],
  [12, 'Parameter Problem'],
  [13, 'Timestamp'],
  [14, 'Timestamp Reply'],
  [15, 'Information Request'],
  [16, 'Information Reply'],
  [17, 'Address Mask Request'],
  [18, 'Address Mask Reply'],
  [19, 'Reserved (for Security)'],
  [30, 'Traceroute'],
  [31, 'Datagram Conversion Error'],
  [32, 'Mobile Host Redirect'],
  [33, 'IPv6 Where-Are-You'],
  [34, 'IPv6 I-Am-Here'],
  [35, 'Mobile Registration Request'],
  [36, 'Mobile Registration Reply'],
  [37, 'Domain Name Request'],
  [38, 'Domain Name Reply'],
  [39, 'SKIP'],
  [40, 'Photuris'],
  [41, 'Seamoby'],
  [42, 'Extended Echo Request'],
  [43, 'Extended Echo Reply'],
  [253, 'RFC3692-style Experiment 1'],
  [254, 'RFC3692-style Experiment 2'],
  [255, 'Reserved 255'],
]);

const ICMP_CODES = new Map<number, Map<number, string>>([
  [3, new Map([
    [0, 'Net Unreachable'],
    [1, 'Host Unreachable'],
    [2, 'Protocol Unreachable'],
    [3, 'Port Unreachable'],
    [4, 'Fragmentation Needed and Don\'t Fragment was Set'],
    [5, 'Source Route Failed'],
    [6, 'Destination Network Unknown'],
    [7, 'Destination Host Unknown'],
    [8, 'Source Host Isolated'],
    [9, 'Communication with Destination Network is Administratively Prohibited'],
    [10, 'Communication with Destination Host is Administratively Prohibited'],
    [11, 'Destination Network Unreachable for Type of Service'],
    [12, 'Destination Host Unreachable for Type of Service'],
    [13, 'Communication Administratively Prohibited'],
    [14, 'Host Precedence Violation'],
    [15, 'Precedence cutoff in effect'],
  ])],
  [5, new Map([
    [0, 'Redirect Datagram for the Network (or subnet)'],
    [1, 'Redirect Datagram for the Host'],
    [2, 'Redirect Datagram for the Type of Service and Network'],
    [3, 'Redirect Datagram for the Type of Service and Host'],
  ])],
  [6, new Map([
    [0, 'Alternate Address for Host'],
  ])],
  [9, new Map([
    [0, 'Normal router advertisement'],
    [16, 'Does not route common traffic'],
  ])],
  [11, new Map([
    [0, 'Time to Live exceeded in Transit'],
    [1, 'Fragment Reassembly Time Exceeded'],
  ])],
  [12, new Map([
    [0, 'Pointer indicates the error'],
    [1, 'Missing a Required Option'],
    [2, 'Bad Length'],
  ])],
  [40, new Map([
    [0, 'Bad SPI'],
    [1, 'Authentication Failed'],
    [2, 'Decompression Failed'],
    [3, 'Decryption Failed'],
    [4, 'Need Authentication'],
    [5, 'Need Authorization'],
  ])],
  [43, new Map([
    [0, 'No Error'],
    [1, 'Malformed Query'],
    [2, 'No Such Interface'],
    [3, 'No Such Table Entry'],
    [4, 'Multiple Interfaces Satisfy Query'],
  ])],
]);

export interface ICMP {
  type: 'icmp';
  itype: string | number;
  code: string | number;
  checksum: number;
  ipv4?: TruncatedIPv4;
  redirectTo?: string;
  id?: number;
  seq?: number;
  originateDate?: Date;
  receiveDate?: Date;
  transmitDate?: Date;
  mask?: string;
  pointer?: number;
  originalLength?: number; // In 32-bit words
  nextHopMTU?: number; // Only if code === 4
  data?: Uint8Array;
}

export interface ICMPtemp {
  itype: number;
}

function msSinceMidnight(ms: number): Date {
  const d = new Date();
  d.setUTCHours(0, 0, 0, ms);
  return d;
}

/**
 * Read an ICMP packet.
 *
 * @param r Reader.
 * @returns Parsed packet.
 * @see https://www.rfc-editor.org/rfc/rfc792
 * @see https://www.rfc-editor.org/rfc/rfc4884
 * @see https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
 */
export function readICMP(r: DataViewReader): ICMP {
  const p = new Packet<ICMP, ICMPtemp>(r);
  p.constant('type', 'icmp')
    .u8('itype', {temp: true})
    .constant('itype', 0, {convert: v => ICMP_TYPES.get(p.temp.itype) ?? v})
    .u8('code', {convert: v => ICMP_CODES.get(p.temp.itype)?.get(v) ?? v})
    .u16('checksum');

  switch (p.temp.itype) {
    case 0: // Echo reply
    case 3: // Destination unreachable
      p.skip(1)
        .u8('originalLength', {convert: l => l * 4})
        .u16('nextHopMTU');
      p.packet.ipv4 = readIPv4Truncated(r);
      break;
    case 4: // Source quench (deprecated)
      p.skip(4);
      p.packet.ipv4 = readIPv4Truncated(r);
      break;
    case 5: // Redirect
      p.packet.redirectTo = ipDecode(r.bytes(4));
      p.packet.ipv4 = readIPv4Truncated(r);
      break;
    case 8: // Echo
      p.u16('id').u16('seq');
      break;
    case 11: // Time exceeded
      p.skip(1)
        .u8('originalLength')
        .skip(2);
      p.packet.ipv4 = readIPv4Truncated(r);
      break;
    case 12: // Parameter Problem
      p.u8('pointer')
        .u8('originalLength')
        .skip(2);
      p.packet.ipv4 = readIPv4Truncated(r);
      break;
    case 13: // Timestamp
    case 14: // Timestamp reply
      p.u16('id')
        .u16('seq')
        .u32('originateDate', {convert: msSinceMidnight})
        .u32('receiveDate', {convert: msSinceMidnight})
        .u32('transmitDate', {convert: msSinceMidnight});
      break;
    case 17: // Address mask request
    case 18: // Address mask reply
      p.u16('id')
        .u16('seq');
      p.packet.mask = ipDecode(r.bytes(4));
      break;
  }

  p.unused('data');

  return p.packet;
}
