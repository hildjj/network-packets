import {type ICMP, type IPv4, type IPv4flags, LINKTYPE_RAW, readPacket} from '../lib/index.js';
import assert from 'node:assert';
import {hex} from './utils.ts';
import {test} from 'node:test';

test('ICMP', async () => {
  await test('dest unreachable', () => {
    const b = hex`
45 00 00 38    # Version (4), IHL (5), TOS (0), Total Length (60 bytes)
A2 22 00 00    # Identification, Flags (DF=0), Fragment Offset (0)
40 01 21 7E    # TTL (64), Protocol (1=ICMP), Header Checksum (example)
C0 A8 01 05    # Source IP: 192.168.1.5
C0 A8 01 64    # Destination IP: 192.168.1.100

# ICMP Header - 8 bytes
03 03 FD 15    # Type (3, Dest Unreachable), Code (3, Port Unreachable), Checksum (example)
00 00 00 00    # Unused (zeros)

# INNER (Original) IPv4 Header + 8 bytes of original data - 28 bytes
# The packet that caused the error

45 00 00 28    # Version (4), IHL (5), TOS (0), Total Length (40 bytes)
00 00 40 00    # Identification, Flags (DF=1), Fragment Offset (0)
FF 11 22 5E    # TTL (255), Protocol (17=UDP), Header Checksum (example)
C0 A8 01 64    # Source IP: 192.168.1.100
C0 A8 01 05    # Destination IP: 192.168.1.5

00 7B 00 35    # Original UDP Src Port (123), Dst Port (53)
00 14 70 E1    # Original UDP Length, Checksum (example)
      `;
    const p = readPacket(b, LINKTYPE_RAW) as IPv4;
    assert.deepEqual(p, {
      type: 'ipv4',
      version: 4,
      IHL: 5,
      DSCP: 0,
      ECN: 0,
      length: 56,
      id: 41506,
      flags: new Set<IPv4flags>(),
      frag_offset: 0,
      ttl: 64,
      checksum: 8574,
      src: '192.168.1.5',
      dest: '192.168.1.100',
      opts: [],
      protocol: 'icmp',
      data: {
        type: 'icmp',
        itype: 'Destination Unreachable',
        code: 'Port Unreachable',
        checksum: 64789,
        originalLength: 0,
        nextHopMTU: 0,
        ipv4: {
          type: 'ipv4',
          version: 4,
          IHL: 5,
          DSCP: 0,
          ECN: 0,
          length: 40,
          id: 0,
          flags: new Set<IPv4flags>(['DF']),
          frag_offset: 0,
          ttl: 255,
          checksum: 8798,
          src: '192.168.1.100',
          dest: '192.168.1.5',
          opts: [],
          protocol: 'udp',
          data: {
            type: 'udp',
            checksum: 28897,
            destPort: 53,
            srcPort: 123,
            length: 20,
          },
        },
      },
    });
  });

  await test('source quench', () => {
    const b = hex`
# OUTER IPv4 Header (ICMP packet) - 20 bytes
# Sent by router 192.168.1.5 to source 192.168.1.100

45 00 00 30    # Version (4), IHL (5), TOS (0), Total Length (48 bytes, 0x30)
A2 22 00 00    # Identification, Flags, Fragment Offset
40 01 21 7E    # TTL (64), Protocol (1=ICMP), Header Checksum (example)
C0 A8 01 05    # Source IP: 192.168.1.5
C0 A8 01 64    # Destination IP: 192.168.1.100

# ICMP Header - 8 bytes
04 00 FD 15    # Type (4, Source Quench), Code (0), Checksum (example value)
00 00 00 00    # Unused (zeros)

# INNER (Original) IPv4 Header + 8 bytes of original data - 28 bytes
# The packet that was dropped or buffered due to congestion

45 00 00 28    # Version (4), IHL (5), TOS (0), Total Length (40 bytes)
00 00 40 00    # Identification, Flags (DF=1), Fragment Offset (0)
FF 11 22 5E    # TTL (255), Protocol (17=UDP), Header Checksum (example)
C0 A8 01 64    # Source IP: 192.168.1.100
C0 A8 01 05    # Destination IP: 192.168.1.5

00 7B 00 35    # Original UDP Src Port (123), Dst Port (53)
00 14 70 E1    # Original UDP Length, Checksum (example)`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv4;
    assert.deepEqual((p.data as ICMP).itype, 'Source Quench');
  });

  await test('redirect', () => {
    const b = hex`
# OUTER IPv4 Header (ICMP packet) - 20 bytes
# Sent by router 192.168.1.1 to host 192.168.1.100

45 00 00 38    # Version (4), IHL (5), TOS (0), Total Length (56 bytes, 0x38)
A2 22 00 00    # Identification, Flags, Fragment Offset
40 01 21 7E    # TTL (64), Protocol (1=ICMP), Header Checksum (example)
C0 A8 01 01    # Source IP: 192.168.1.1 (Current Gateway)
C0 A8 01 64    # Destination IP: 192.168.1.100 (Host)

# ICMP Header and Gateway IP - 8 bytes + 4 bytes = 12 bytes total
05 00 FD 15    # Type (5, Redirect), Code (0, Redirect for Network), Checksum (example)
C0 A8 01 FE    # Gateway Internet Address: 192.168.1.254 (The *better* gateway IP)

# INNER (Original) IPv4 Header + 8 bytes of original data - 28 bytes
# The packet that triggered the redirect

45 00 00 28    # Version (4), IHL (5), TOS (0), Total Length (40 bytes)
00 00 40 00    # Identification, Flags (DF=1), Fragment Offset (0)
FF 06 22 5E    # TTL (255), Protocol (6=TCP), Header Checksum (example)
C0 A8 01 64    # Source IP: 192.168.1.100
10 00 00 01    # Destination IP: 10.0.0.1 (Remote destination host)

00 7B 00 35    # Original TCP Src Port/Dst Port (example data)
00 14 70 E1    # Original TCP Sequence Number start (example data)`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv4;
    assert.deepEqual((p.data as ICMP).itype, 'Redirect');
  });

  await test('time exceeded', () => {
    const b = hex`
# OUTER IPv4 Header (ICMP packet) - 20 bytes
# Sent by router 10.0.0.5 back to host 192.168.1.100

45 00 00 38    # Version (4), IHL (5), TOS (0), Total Length (56 bytes, 0x38)
A2 22 00 00    # Identification, Flags, Fragment Offset
01 01 21 7E    # TTL (1), Protocol (1=ICMP), Header Checksum (example)
0A 00 00 05    # Source IP: 10.0.0.5 (Router where packet died)
C0 A8 01 64    # Destination IP: 192.168.1.100 (Original sender)

# ICMP Header - 8 bytes
0B 00 FD 15    # Type (11, Time Exceeded), Code (0, TTL expired in transit), Checksum (example)
00 00 00 00    # Unused (zeros)

# INNER (Original) IPv4 Header + 8 bytes of original data - 28 bytes
# The packet that had its TTL expire

45 00 00 28    # Version (4), IHL (5), TOS (0), Total Length (40 bytes)
00 00 40 00    # Identification, Flags (DF=1), Fragment Offset (0)
01 06 22 5E    # TTL (1, was decremented to 0), Protocol (6=TCP), Header Checksum (example)
C0 A8 01 64    # Source IP: 192.168.1.100
10 00 00 01    # Destination IP: 10.0.0.1 (Target destination)

00 7B 00 35    # Original TCP Src Port/Dst Port (example data)
00 14 70 E1    # Original TCP Sequence Number start (example data)`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv4;
    assert.deepEqual((p.data as ICMP).itype, 'Time Exceeded');
  });

  await test('parameter problem', () => {
    const b = hex`
# OUTER IPv4 Header (ICMP packet) - 20 bytes
# Sent by router 192.168.1.5 back to host 192.168.1.100

45 00 00 38    # Version (4), IHL (5), TOS (0), Total Length (56 bytes, 0x38)
A2 22 00 00    # Identification, Flags, Fragment Offset
40 01 21 7E    # TTL (64), Protocol (1=ICMP), Header Checksum (example)
C0 A8 01 05    # Source IP: 192.168.1.5
C0 A8 01 64    # Destination IP: 192.168.1.100

# ICMP Header - 8 bytes
0C 00 FD 15    # Type (12, Parameter Problem), Code (0), Checksum (example)
08 00 00 00    # Pointer: Points to byte 8 (TTL field) of the original IP header

# INNER (Original) IPv4 Header + 8 bytes of original data - 28 bytes
# The invalid packet that was dropped

45 00 00 28    # Version (4), IHL (5), TOS (0), Total Length (40 bytes)
00 00 40 00    # Identification, Flags (DF=1), Fragment Offset (0)
FF 06 22 5E    # Header Checksum (example)
C0 A8 01 64    # Source IP: 192.168.1.100
10 00 00 01    # Destination IP: 10.0.0.1 (Target destination)
# Note: The TTL byte (offset 8) is missing in the above display for clarity
# but it is present in the actual packet data starting with C0 A8 01 64

00 7B 00 35    # Original TCP Src Port/Dst Port (example data)
00 14 70 E1    # Original TCP Sequence Number start (example data)`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv4;
    assert.deepEqual((p.data as ICMP).itype, 'Parameter Problem');
  });

  await test('timestamp request', () => {
    const b = hex`
# OUTER IPv4 Header (ICMP packet) - 20 bytes
# Sent by router 192.168.1.5 back to host 192.168.1.100

45 00 00 38    # Version (4), IHL (5), TOS (0), Total Length (56 bytes, 0x38)
A2 22 00 00    # Identification, Flags, Fragment Offset
40 01 21 7E    # TTL (64), Protocol (1=ICMP), Header Checksum (example)
C0 A8 01 05    # Source IP: 192.168.1.5
C0 A8 01 64    # Destination IP: 192.168.1.100

# ICMP Header - 8 bytes
0D 00 FD 15    # Type (13, Timestamp Request), Code (0), Checksum (example)
00 01 00 05    # ICMP Data: Identifier (0x0001), Sequence Number (0x0005)
04 19 6E 18    # ICMP Data: Originate Timestamp (68765000 ms since midnight UT)
00 00 00 00    # ICMP Data: Receive Timestamp (placeholder 0)
00 00 00 00    # ICMP Data: Transmit Timestamp (placeholder 0)
`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv4;
    assert.deepEqual((p.data as ICMP).itype, 'Timestamp');
  });

  await test('timestamp request', () => {
    const b = hex`
# OUTER IPv4 Header (ICMP packet) - 20 bytes
# Sent by router 192.168.1.5 back to host 192.168.1.100

45 00 00 38    # Version (4), IHL (5), TOS (0), Total Length (56 bytes, 0x38)
A2 22 00 00    # Identification, Flags, Fragment Offset
40 01 21 7E    # TTL (64), Protocol (1=ICMP), Header Checksum (example)
C0 A8 01 05    # Source IP: 192.168.1.5
C0 A8 01 64    # Destination IP: 192.168.1.100

# ICMP Header - 8 bytes
0E 00 FD 15    # Type (14, Timestamp Reply), Code (0), Checksum (example)
00 01 00 05    # ICMP Data: Identifier (0x0001), Sequence Number (0x0005)
04 19 6E 18    # ICMP Data: Originate Timestamp (68765000 ms since midnight UT)
04 19 6E 19    # ICMP Data: Receive Timestamp
04 19 6E 20    # ICMP Data: Transmit Timestamp
`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv4;
    assert.deepEqual((p.data as ICMP).itype, 'Timestamp Reply');
  });

  await test('address mask request', () => {
    const b = hex`
# OUTER IPv4 Header (ICMP packet) - 20 bytes
# Sent by router 192.168.1.5 back to host 192.168.1.100

45 00 00 38    # Version (4), IHL (5), TOS (0), Total Length (56 bytes, 0x38)
A2 22 00 00    # Identification, Flags, Fragment Offset
40 01 21 7E    # TTL (64), Protocol (1=ICMP), Header Checksum (example)
C0 A8 01 05    # Source IP: 192.168.1.5
C0 A8 01 64    # Destination IP: 192.168.1.100

# ICMP Header - 8 bytes
11 00 FD 15    # Type (17, Address Map Request), Code (0), Checksum (example)
00 01 00 05    # ICMP Data: Identifier (0x0001), Sequence Number (0x0005)
00 00 00 00    # Request is all 0's
`;
    const p = readPacket(b, LINKTYPE_RAW) as IPv4;
    assert.deepEqual((p.data as ICMP).itype, 'Address Mask Request');
  });
});
