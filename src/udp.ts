import {DataViewReader, Packet} from 'dataview-stream/packet';

export const UDP_PROTO = 17;

export interface UDP {
  type: 'udp';
  srcPort: number;
  destPort: number;
  length: number;
  checksum: number;
  data: Uint8Array;
}

/**
 * Decode a User Datagram Protocol packet.
 *
 * @param r Reader.
 * @returns Decoded packet.
 * @see https://www.rfc-editor.org/rfc/rfc768
 */
export function readUDP(r: DataViewReader): UDP {
  const p = new Packet<UDP>(r);
  return p.constant('type', 'udp')
    .u16('srcPort')
    .u16('destPort')
    .u16('length')
    .u16('checksum')
    .bytes('data', p.packet.length - 8)
    .packet;
}
