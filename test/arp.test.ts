import {LINKTYPE_ETHERNET, readPacket} from '../src/index.ts';
import {assert, describe, test} from 'vitest';
import {hex} from './utils.ts';

describe('ARP', () => {
  test('edges', () => {
    const p = readPacket(hex`
ffffffffffff 00070daff454 0806
  fff0 0800 06 04 fff0 00070daff454 18a6ac01
  000000000000 18a6ad9f`, LINKTYPE_ETHERNET);
    assert.deepEqual(p, {
      type: 'ethernet',
      dest: 'FF:FF:FF:FF:FF:FF',
      src: '00:07:0D:AF:F4:54',
      tags: [],
      etherType: 'ARP',
      data: {
        type: 'arp',
        hardware: 65520,
        protocol: 2048,
        op: 65520,
        senderHardware: '00:07:0D:AF:F4:54',
        senderProtocol: '24.166.172.1',
        targetHardware: '00:00:00:00:00:00',
        targetProtocol: '24.166.173.159',
      },
    });
  });
});
