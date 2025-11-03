import {DataViewReader, Packet} from 'dataview-stream/packet';
import {bytesToMac} from './utils.ts';
import {decode as ipDecode} from '@leichtgewicht/ip-codec';

export const ARP_ETHERTYPE = 0x0806;

const ARP_OPCODES = new Map<number, string>([
  [0, 'Reserved 0'],
  [1, 'REQUEST'],
  [2, 'REPLY'],
  [3, 'request Reverse'],
  [4, 'reply Reverse'],
  [5, 'DRARP-Request'],
  [6, 'DRARP-Reply'],
  [7, 'DRARP-Error'],
  [8, 'InARP-Request'],
  [9, 'InARP-Reply'],
  [10, 'ARP-NAK'],
  [11, 'MARS-Request'],
  [12, 'MARS-Multi'],
  [13, 'MARS-MServ'],
  [14, 'MARS-Join'],
  [15, 'MARS-Leave'],
  [16, 'MARS-NAK'],
  [17, 'MARS-Unserv'],
  [18, 'MARS-SJoin'],
  [19, 'MARS-SLeave'],
  [20, 'MARS-Grouplist-Request'],
  [21, 'MARS-Grouplist-Reply'],
  [22, 'MARS-Redirect-Map'],
  [23, 'MAPOS-UNARP'],
  [24, 'OP_EXP1'],
  [25, 'OP_EXP2'],
  [65535, 'Reserved 65535'],
]);

const ARP_HARDWARE = new Map<number, string>([
  [0, 'Reserved 0'],
  [1, 'Ethernet (10Mb)'],
  [2, 'Experimental Ethernet (3Mb)'],
  [3, 'Amateur Radio AX.25'],
  [4, 'Proteon ProNET Token Ring'],
  [5, 'Chaos'],
  [6, 'IEEE 802 Networks'],
  [7, 'ARCNET'],
  [8, 'Hyperchannel'],
  [9, 'Lanstar'],
  [10, 'Autonet Short Address'],
  [11, 'LocalTalk'],
  [12, 'LocalNet (IBM PCNet or SYTEK LocalNET)'],
  [13, 'Ultra link'],
  [14, 'SMDS'],
  [15, 'Frame Relay'],
  [16, 'Asynchronous Transmission Mode (ATM)'],
  [17, 'HDLC'],
  [18, 'Fibre Channel'],
  [19, 'Asynchronous Transmission Mode (ATM)'],
  [20, 'Serial Line'],
  [21, 'Asynchronous Transmission Mode (ATM)'],
  [22, 'MIL-STD-188-220'],
  [23, 'Metricom'],
  [24, 'IEEE 1394.1995'],
  [25, 'MAPOS'],
  [26, 'Twinaxial'],
  [27, 'EUI-64'],
  [28, 'HIPARP'],
  [29, 'IP and ARP over ISO 7816-3'],
  [30, 'ARPSec'],
  [31, 'IPsec tunnel'],
  [32, 'InfiniBand (TM)'],
  [33, 'TIA-102 Project 25 Common Air Interface (CAI)'],
  [34, 'Wiegand Interface'],
  [35, 'Pure IP'],
  [36, 'HW_EXP1'],
  [37, 'HFI'],
  [38, 'Unified Bus (UB)'],
  [256, 'HW_EXP2'],
  [257, 'AEthernet'],
  [65535, 'Reserved 65535'],
]);

export interface ARP {
  type: 'arp';
  hardware: string | number;
  protocol: number;
  op: string | number;
  senderHardware: string;
  senderProtocol: string;
  targetHardware: string;
  targetProtocol: string;
}

interface ARPtemp {
  hlen: number;
  plen: number;
}

/**
 * Decode an Address Resolution Protocol packet.
 *
 * @param r Reader.
 * @returns Decoded packet.
 * @see https://www.rfc-editor.org/rfc/rfc826
 */
export function readARP(r: DataViewReader): ARP {
  const p = new Packet<ARP, ARPtemp>(r);
  return p.constant('type', 'arp')
    .u16('hardware', {convert: v => ARP_HARDWARE.get(v) ?? v})
    .u16('protocol')
    .u8('hlen', {temp: true})
    .u8('plen', {temp: true})
    .u16('op', {convert: v => ARP_OPCODES.get(v) ?? v})
    .bytes('senderHardware', p.temp.hlen, {convert: v => bytesToMac(v)})
    .bytes('senderProtocol', p.temp.plen, {convert: v => ipDecode(v)})
    .bytes('targetHardware', p.temp.hlen, {convert: v => bytesToMac(v)})
    .bytes('targetProtocol', p.temp.plen, {convert: v => ipDecode(v)})
    .packet;
}
