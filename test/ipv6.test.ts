import {type IPv6, LINKTYPE_RAW, readPacket} from '../src/index.ts';
import {assert, describe, test} from 'vitest';
import {Buffer} from 'node:buffer';
import {hex} from './utils.ts';

describe('IPv6', () => {
  test('extensions', () => {
    const b = hex`
# IPv6 Base Header (40 bytes)
60 00 00 00       # Version (6), Traffic Class (0), Flow Label (0)
00 10             # Payload Length: 16 bytes (UDP payload length, 0x0010)
00                # Next Header: 0 (Hop-by-Hop Options Header follows)
40                # Hop Limit: 64

# Source Address: 2001:db8:85a3::8a2e:370:7334
20 01 0d b8 85 a3 00 00 00 00 8a 2e 03 70 73 34

# Destination Address: 2001:db8:85a3::8a2e:370:7335
20 01 0d b8 85 a3 00 00 00 00 8a 2e 03 70 73 35

# Hop-by-Hop Options Header (8 bytes)
11                # Next Header: 17 (UDP header follows this extension header)
00                # Header Ext Length: 0 (Header is 0*8 + 8 = 8 bytes long)
01 02 00 00 00 00 # Options: Example option data (e.g. Pad1 or PadN for alignment)

# UDP Header and Payload (16 bytes total)
# (Source Port: 1234, Dest Port: 8080)
04 D2             # Source Port: 1234
1F 90             # Destination Port: 8080
00 10             # Length: 16 bytes (0x0010)
F7 F0             # Checksum (example value)
# UDP Payload data
48 65 6C 6C 6F 21 0A 00 # Data: "Hello!"`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv6;
    assert.deepEqual(p.data, {
      type: 'udp',
      srcPort: 1234,
      destPort: 8080,
      checksum: 0xF7F0,
      length: 16,
      data: Buffer.from('Hello!\n\x00'),
    });
  });

  test('no next header', () => {
    const b = hex`
# IPv6 Base Header (40 bytes)
60 00 00 00       # Version (6), Traffic Class (0), Flow Label (0)
00 10             # Payload Length: 16 bytes (ignored payload length, 0x0010)
3B                # Next Header: 59 (no next header)
40                # Hop Limit: 64

# Source Address: 2001:db8:85a3::8a2e:370:7334
20 01 0d b8 85 a3 00 00 00 00 8a 2e 03 70 73 34

# Destination Address: 2001:db8:85a3::8a2e:370:7335
20 01 0d b8 85 a3 00 00 00 00 8a 2e 03 70 73 35
`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv6;
    assert.deepEqual(p.data, Buffer.alloc(0));
  });

  test('unknown L4', () => {
    const b = hex`
# IPv6 Base Header (40 bytes)
60 00 00 00       # Version (6), Traffic Class (0), Flow Label (0)
00 01             # Payload Length: 16 bytes (payload length, 1)
FC                # Next Header: 252 (not assigned)
40                # Hop Limit: 64

# Source Address: 2001:db8:85a3::8a2e:370:7334
20 01 0d b8 85 a3 00 00 00 00 8a 2e 03 70 73 34

# Destination Address: 2001:db8:85a3::8a2e:370:7335
20 01 0d b8 85 a3 00 00 00 00 8a 2e 03 70 73 35

# One byte
01`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv6;
    assert.equal(p.protocol, 252);
  });
});
