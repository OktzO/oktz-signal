import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('main package tarball contains no native binary', () => {
  const [{ files }] = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: root,
    encoding: 'utf8',
  }));

  assert.equal(files.some(({ path }) => path.endsWith('.node')), false);
  assert.equal(files.some(({ path }) => path.startsWith('native/signal/target/')), false);
});
