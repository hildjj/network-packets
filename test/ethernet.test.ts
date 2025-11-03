import {LINKTYPE_ETHERNET, readPacket} from '../src/index.ts';
import {assert, describe, test} from 'vitest';
import {Buffer} from 'node:buffer';
import {hex} from './utils.ts';

describe('ethernet', () => {
  test('length', () => {
    const p = readPacket(hex`
ffffffffffff 00070daff454 0002
  61 62`, LINKTYPE_ETHERNET);
    assert.deepEqual(p, {
      type: 'ethernet',
      dest: 'FF:FF:FF:FF:FF:FF',
      src: '00:07:0D:AF:F4:54',
      etherType: 'length',
      length: 2,
      tags: [],
      data: Buffer.from('ab'),
    });
  });

  test('unknown ethertype', () => {
    const p = readPacket(hex`
ffffffffffff 00070daff454 cdef
  61 62
      `, LINKTYPE_ETHERNET);
    assert.deepEqual(p, {
      type: 'ethernet',
      dest: 'FF:FF:FF:FF:FF:FF',
      src: '00:07:0D:AF:F4:54',
      etherType: 0xcdef,
      tags: [],
      data: Buffer.from('ab'),
    });
  });
});
