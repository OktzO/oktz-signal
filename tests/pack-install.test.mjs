import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('main package tarball ships exactly the one platform binary it is built for', () => {
  const [{ files }] = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: root,
    encoding: 'utf8',
  }));

  // The 0.3.0-rc.2 packaging bundles the binding rather than resolving it from
  // the @oktz-signal/* platform packages, which do not exist on the registry —
  // a tarball without any binary is not installable. So the invariant is now
  // "exactly the linux-x64-gnu build, and no build output", not "no binary".
  const binaries = files.filter(({ path }) => path.endsWith('.node')).map(({ path }) => path);
  assert.deepEqual(binaries, ['native/signal/signal.linux-x64-gnu.node']);
  assert.equal(files.some(({ path }) => path.startsWith('native/signal/target/')), false);
  assert.equal(files.some(({ path }) => path.endsWith('.cjs.generated')), false);
});
