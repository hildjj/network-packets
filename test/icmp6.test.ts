import {type ICMP6, type IPv6, LINKTYPE_RAW, readPacket} from '../lib/index.js';
import assert from 'node:assert';
import {hex} from './utils.ts';
import {test} from 'node:test';

test('ICMP6', async () => {
  await test('Neighbor Solicitation', () => {
    const b = hex`
# IPv6 Base Header (40 bytes)
60 00 00 00       # Version (6), Traffic Class (0), Flow Label (0)
00 20             # Payload Length: 32 bytes (Length of ICMPv6 NS message, 0x0020)
3A                # Next Header: 58 (ICMPv6)
FF                # Hop Limit: 255

# Source Address: 2001:db8:1::100
20 01 0d b8 00 01 00 00 00 00 00 00 00 00 01 00

# Destination Address: FF02::1:FF00:1 (Solicited-Node Multicast for 2001:db8:1::1)
FF 02 00 00 00 00 00 00 00 00 00 01 FF 00 00 01

# ICMPv6 Neighbor Solicitation Message (32 bytes)
87                # Type: 135 (Neighbor Solicitation)
00                # Code: 0
6C 0C             # Checksum (example value)
00 00 00 00       # Flags (Reserved, must be zero)

# Target Address: 2001:db8:1::1 (The address whose MAC we are soliciting)
20 01 0d b8 00 01 00 00 00 00 00 00 00 00 00 01

# Options (Optional, but often included: Source Link-Layer Address option)
01                # Type: 1 (Source Link-Layer Address)
01                # Length: 1 (1*8 = 8 bytes total length for option)
AA BB CC DD EE FF # Link-Layer Address (MAC Address of the sender)
65                # Unknown option
02                # 16 bytes
0001020304050607
000102030405`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv6;
    assert.deepEqual(p.data, {
      type: 'ipv6_icmp',
      messageType: 'Neighbor Solicitation',
      error: false,
      code: 0,
      checksum: 27660,
      data: {
        type: 'NeighborSolicitation',
        target: '2001:db8:1::1',
        options: [
          {
            type: 'Source Link-layer Address',
            length: 8,
            data: hex`AA BB CC DD EE FF`,
          },
          {
            type: 101,
            length: 16,
            data: hex`0001020304050607 000102030405`,
          },
        ],
      },
    });
  });

  await test('Packet too big', () => {
    const b = hex`
# OUTER IPv6 Base Header (40 bytes)
60 00 00 00       # Version (6), Traffic Class (0), Flow Label (0)
00 50             # Payload Length: 80 bytes (0x0050, the full ICMPv6 message)
3A                # Next Header: 58 (ICMPv6)
FF                # Hop Limit: 255

# Source Address: 2001:db8:a::1 (Router sending the error)
20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01

# Destination Address: 2001:db8:1::100 (Original sender)
20 01 0d b8 00 01 00 00 00 00 00 00 00 00 01 00

# ICMPv6 Packet Too Big Message (80 bytes total for the payload)
02                # Type: 2 (Packet Too Big)
00                # Code: 0
6C 0C             # Checksum (calculated value, example)

00 00 05 00       # MTU of the Next-Hop Link: 1280 bytes (0x0500)
00 00 00 00       # Reserved field (must be zero)

# Original (Inner) IPv6 Packet starts here (Full contents of the packet that was dropped)

# Inner IPv6 Header
60 00 00 00       # Inner Version (6), TC (0), FL (0)
00 10             # Inner Payload Length: 16 bytes (UDP payload)
11                # Inner Next Header: 17 (UDP)
40                # Inner Hop Limit: 64

# Inner Source Address: 2001:db8:1::100
20 01 0d b8 00 01 00 00 00 00 00 00 00 00 01 00

# Inner Destination Address: 2001:db8:z::1
20 01 0d b8 00 7a 00 00 00 00 00 00 00 00 00 01

# Inner UDP Header and Payload
04 D2             # Source Port: 1234
1F 90             # Destination Port: 8080
00 10             # Length: 16 bytes (0x0010)
F7 F0             # Checksum (example value)
48 65 6C 6C 6F 21 0A 00 # Data: "Hello!\n\0"
    `;
    const p = readPacket(b, LINKTYPE_RAW) as IPv6;
    assert.equal((p.data as ICMP6).messageType, 'Packet Too Big');
  });

  await test('parameter problem', () => {
    const b = hex`
# OUTER IPv6 Base Header (40 bytes)
60 00 00 00       # Version (6), Traffic Class (0), Flow Label (0)
00 4C             # Payload Length: 76 bytes (0x004C, the full ICMPv6 message)
3A                # Next Header: 58 (ICMPv6)
FF                # Hop Limit: 255

# Source Address: 2001:db8:a::1 (Router sending the error)
20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01

# Destination Address: 2001:db8:1::100 (Original sender)
20 01 0d b8 00 01 00 00 00 00 00 00 00 00 01 00

# ICMPv6 Parameter Problem Message (76 bytes total for the payload)
04                # Type: 4 (Parameter Problem)
00                # Code: 0 (Erroneous header field encountered)
6C 0C             # Checksum (calculated value, example)

00 00 00 07       # Pointer: Points to byte 7 (Hop Limit field) of the original packet
                  # The pointer is 4 bytes long but points to a single byte offset.

# Original (Inner) IPv6 Packet starts here (Full contents of the packet that was dropped)

# Inner IPv6 Header
60 00 00 00       # Inner Version (6), TC (0), FL (0)
00 10             # Inner Payload Length: 16 bytes (UDP payload)
11                # Inner Next Header: 17 (UDP)
FF                # Inner Hop Limit: 255 (This is the field causing the problem/error)

# Inner Source Address: 2001:db8:1::100
20 01 0d b8 00 01 00 00 00 00 00 00 00 00 01 00

# Inner Destination Address: 2001:db8:z::1
20 01 0d b8 00 7a 00 00 00 00 00 00 00 00 00 01

# Inner UDP Header and Payload
04 D2             # Source Port: 1234
1F 90             # Destination Port: 8080
00 10             # Length: 16 bytes (0x0010)`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv6;
    assert.deepEqual((p.data as ICMP6).messageType, 'Parameter Problem');
  });

  await test('unknown message type', () => {
    const b = hex`
# OUTER IPv6 Base Header (40 bytes)
60 00 00 00       # Version (6), Traffic Class (0), Flow Label (0)
00 4C             # Payload Length: 76 bytes (0x004C, the full ICMPv6 message)
3A                # Next Header: 58 (ICMPv6)
FF                # Hop Limit: 255

# Source Address: 2001:db8:a::1 (Router sending the error)
20 01 0d b8 00 0a 00 00 00 00 00 00 00 00 00 01

# Destination Address: 2001:db8:1::100 (Original sender)
20 01 0d b8 00 01 00 00 00 00 00 00 00 00 01 00

# ICMPv6 Parameter Problem Message (76 bytes total for the payload)
FA                # Type: 250 (Unknown)
00                # Code: 0 (Erroneous header field encountered)
6C 0C             # Checksum (calculated value, example)`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv6;
    assert.equal((p.data as ICMP6).messageType, 250);
  });
});
