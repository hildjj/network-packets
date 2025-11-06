import {LINKTYPE_ETHERNET, readPacket} from '../lib/index.js';
import {Buffer} from 'node:buffer';
import assert from 'node:assert';
import {hex} from './utils.ts';
import {test} from 'node:test';

test('ethernet', async () => {
  await test('length', () => {
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

  await test('unknown ethertype', () => {
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
