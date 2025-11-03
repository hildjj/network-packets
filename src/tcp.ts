import {DataViewReader, Packet} from 'dataview-stream/packet';

export const TCP_PROTO = 6;

export type TCPflag = 'CWR' | 'ECE' | 'URG' | 'ACK' | 'PSH' | 'RST' | 'SYN' | 'FIN';

export interface TCP {
  type: 'tcp';
  srcPort: number;
  destPort: number;
  seq: number;
  ack: number;
  offset: number;
  flags: Set<TCPflag>;
  window: number;
  checksum: number;
  urgent: number;
  opts: number[];
  data: Uint8Array;
}

interface TCPtemp {
  off: number;
  flags: number;
}

const FLAGS = {
  ECE: 6,
  URG: 5,
  ACK: 4,
  PSH: 3,
  RST: 2,
  SYN: 1,
  FIN: 0,
};

/**
 * Decode a TCP header.
 *
 * @param r Reader.
 * @returns Decoded packet.
 * @see https://www.rfc-editor.org/rfc/rfc9293#name-header-format
 */
export function readTCP(r: DataViewReader): TCP {
  const p = new Packet<TCP, TCPtemp>(r);
  p.constant('type', 'tcp')
    .u16('srcPort')
    .u16('destPort')
    .u32('seq')
    .u32('ack')
    .u8('off', {temp: true})
    .bits({fromTemp: 'off', to: 'offset', start: 7, finish: 4})
    .u8('flags', {temp: true})
    .bits({fromTemp: 'flags', to: 'flags', set: FLAGS})
    .u16('window')
    .u16('urgent')
    .times('opts', p.packet.offset - 5, () => r.u32()) // TODO: extract options
    .unused('data');
  return p.packet;
}
