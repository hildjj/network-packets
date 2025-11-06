import {type IPv4, LINKTYPE_NULL, LINKTYPE_RAW, readPacket} from '../lib/index.js';
import {PCAPNGParser} from '@cto.af/pcap-ng-parser';
import type {ReadStream} from 'node:fs';
import assert from 'node:assert';
import fs from 'node:fs/promises';
import {hex} from './utils.ts';
import {test} from 'node:test';

const DATA = new URL('./data/', import.meta.url);

function readFile(s: ReadStream, _fn: string): Promise<[number, number]> {
  let er = 0;
  let count = 0;
  return new Promise((resolve, reject) => {
    const p = new PCAPNGParser();
    s.pipe(p)
      .on('error', e => {
        reject(e as Error);
      })
      .on('close', () => {
        resolve([er, count]);
      })
      .on('data', d => {
        try {
          readPacket(d.data, p.interfaces[d.interfaceId].linkType);
          count++;
        } catch (_e) {
          //
          // console.error(`Error in ${fn}: ${e}`);
          er++;
        }
      });
  });
}

test('data files', async () => {
  const dirFiles = await fs.readdir(DATA);
  for (const fn of dirFiles) {
    await test(`File: ${fn}`, async () => {
      const u = new URL(fn, DATA);
      const s = (await fs.open(u)).createReadStream();
      const [e, c] = await readFile(s, fn);
      assert.equal(e, 0);
      assert(c > 0);
    });
  }
});

test('readPacket', async () => {
  await test('LINKTYPE_NULL', () => {
    const b = hex`
00 00 00 02    # IPv4 packet

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
00 00 00 00    # Request is all 0's `;
    const p = readPacket(b, LINKTYPE_NULL) as IPv4;
    assert.equal(p.protocol, 'icmp');
  });

  await test('empty', () => {
    assert.throws(() => readPacket(hex``, LINKTYPE_RAW));
  });

  await test('invalid IP version', () => {
    assert.throws(() => readPacket(hex`50`, LINKTYPE_RAW));
  });

  await test('invalid link type', () => {
    assert.throws(() => readPacket(hex`60`, 65000));
  });
});
