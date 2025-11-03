import {DOT1Q_ETHERTYPE, ETHERTYPES, type L3, L3_DECODERS, QINQ_ETHERTYPE} from './L3.ts';
import {DataViewReader, Packet} from 'dataview-stream/packet';
import {bytesToMac} from './utils.ts';

export interface Ethernet {
  type: 'ethernet';
  dest: string;
  src: string;
  etherType: string | number;
  et?: number;
  length?: number;
  tags: number[];
  data: L3;
}

interface EthernetTemp {
  etherType: number;
}

const TAG_ETHERTYPES = new Set<string | number>([
  DOT1Q_ETHERTYPE, QINQ_ETHERTYPE,
]);

/**
 * Read an Ethernet packet, decoding as much of it as possible.
 *
 * @param r Reader.
 * @returns Decoded packet.
 */
export function readEthernet(r: DataViewReader): Ethernet {
  const p = new Packet<Ethernet, EthernetTemp>(r);
  p.constant('type', 'ethernet')
    .bytes('dest', 6, {convert: v => bytesToMac(v)})
    .bytes('src', 6, {convert: v => bytesToMac(v)})
    .u16('etherType', {temp: true})
    .while(
      'tags',
      () => TAG_ETHERTYPES.has(p.temp.etherType),
      () => {
        const ret = r.u16(); // Tag
        p.u16('etherType', {temp: true});
        return ret;
      }
    );

  const eth = ETHERTYPES.get(p.temp.etherType);
  if (typeof eth !== 'undefined') {
    p.packet.etherType = eth;
  } else if (p.temp.etherType < 1536) {
    p.packet.length = p.temp.etherType;
    p.packet.etherType = 'length';
  } else {
    p.packet.etherType = p.temp.etherType;
  }

  const decoder = L3_DECODERS.get(p.temp.etherType);
  p.packet.data = decoder ? decoder(r) : r.unused();
  return p.packet;
}
