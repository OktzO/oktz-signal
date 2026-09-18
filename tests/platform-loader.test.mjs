import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { native } from '../index.js';

const packageRoot = dirname(fileURLToPath(import.meta.url));
const root = join(packageRoot, '..');

test('loads native module through platform loader', () => {
  assert.equal(typeof native.curveSign, 'function');
  assert.equal(typeof native.ratchetEncrypt, 'function');
  assert.equal(native.default, native);
});

test('packed package loads native module from optional platform package', () => {
  const workspace = mkdtempSync(join(tmpdir(), 'oktz-signal-'));
  const platformDir = join(root, 'npm', 'linux-x64-gnu');
  const platformBinary = join(platformDir, 'signal.linux-x64-gnu.node');
  let mainTarball;
  let platformTarball;

  try {
    const [{ filename: mainFilename }] = JSON.parse(execFileSync('npm', ['pack', '--json'], { cwd: root }));
    cpSync(join(root, 'native', 'signal', 'signal.linux-x64-gnu.node'), platformBinary);
    const [{ filename: platformFilename }] = JSON.parse(execFileSync('npm', ['pack', '--json'], { cwd: platformDir }));
    mainTarball = join(root, mainFilename);
    platformTarball = join(platformDir, platformFilename);
    execFileSync('npm', ['install', '--ignore-scripts', '--offline', '--no-audit', '--no-fund', mainTarball, platformTarball], { cwd: workspace });

    const output = execFileSync(process.execPath, ['--input-type=module', '--eval', "import { native } from 'oktz-signal'; console.log(typeof native.curveSign, native.default === native)"], { cwd: workspace, encoding: 'utf8' });
    assert.equal(output.trim(), 'function true');
  } finally {
    rmSync(workspace, { force: true, recursive: true });
    if (mainTarball) rmSync(mainTarball, { force: true });
    if (platformTarball) rmSync(platformTarball, { force: true });
    rmSync(platformBinary, { force: true });
  }
});
