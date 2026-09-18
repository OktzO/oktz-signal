import assert from 'node:assert/strict';
import test from 'node:test';
import { native } from '../index.js';

test('loads native module through platform loader', () => {
  assert.equal(typeof native.curveSign, 'function');
  assert.equal(typeof native.ratchetEncrypt, 'function');
});
