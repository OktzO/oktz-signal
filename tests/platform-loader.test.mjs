import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { native } from '../index.js';

test('loads native module through platform loader', () => {
  assert.equal(typeof native.curveSign, 'function');
  assert.equal(typeof native.ratchetEncrypt, 'function');
  assert.equal(native.default, native);
});

test('packed package loads native module from optional platform package', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'oktz-signal-'));
  const platformPackage = join(workspace, 'node_modules', '@oktz-signal', 'signal-linux-x64-gnu');
  const packageRoot = join(import.meta.dirname, '..');
  let tarball;

  try {
    const packed = execFileSync('npm', ['pack', '--json'], { cwd: packageRoot });
    const [{ filename }] = JSON.parse(packed);
    tarball = join(packageRoot, filename);
    execFileSync('tar', ['-xzf', tarball, '-C', workspace]);
    mkdirSync(platformPackage, { recursive: true });
    cpSync(join(packageRoot, 'npm', 'linux-x64-gnu', 'package.json'), join(platformPackage, 'package.json'));
    cpSync(join(packageRoot, 'native', 'signal', 'signal.linux-x64-gnu.node'), join(platformPackage, 'signal.linux-x64-gnu.node'));

    const output = execFileSync(process.execPath, ['--input-type=module', '--eval', "import { native } from './package/index.js'; console.log(typeof native.curveSign, native.default === native)"], { cwd: workspace, encoding: 'utf8' });
    assert.equal(output.trim(), 'function true');
  } finally {
    rmSync(workspace, { force: true, recursive: true });
    if (tarball) rmSync(tarball, { force: true });
  }
});
