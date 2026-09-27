// native/signal/index.cjs is emitted by `napi build` and then hand-patched, and
// the patches are not cosmetic: they are the seven hardening fixes the loader
// carries (unconditional version check, scoped process.report mutation, silent
// libc probe, platform fallbacks after a bad NAPI_RS_NATIVE_LIBRARY_PATH,
// absent-WASI-candidate suppression, gated npm advice) plus the
// `module.exports.default` line. `prepublishOnly` used to run the very same
// `napi build` over the committed file, so `npm publish` regenerated it,
// reverted all of it, and printed a normal success.
//
// These tests never assert that the committed loader "looks right" -- that is
// the state the repo is already in. They render a *real* regenerated loader
// with the generator the build uses (@napi-rs/cli's own writeJsBinding, no Rust
// involved) and drive the publish guard against it, so the input is what a
// regeneration would actually produce rather than a hand-written stand-in.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { writeJsBinding } from '@napi-rs/cli';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const guard = join(root, 'scripts', 'loader-guard.mjs');
const loaderPath = join(root, 'native', 'signal', 'index.cjs');
const committed = readFileSync(loaderPath, 'utf8');

const { binaryName } = JSON.parse(readFileSync(join(root, 'napi.config.json'), 'utf8'));
const { version } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

// The inputs `npm run build:native` hands the generator. `binaryName` and
// `version` are read from the files the CLI itself reads; the package name is
// the literal in that script's `--js-package-name`; IDENTS are the 16 `#[napi]`
// exports the addon publishes, in the order napi-rs emits them. Adding an
// export changes IDENTS, which fails the byte-equality test below and forces a
// deliberate loader regeneration instead of a silent omission.
const JS_PACKAGE_NAME = '@oktz-signal/signal';
const IDENTS = [
  'curveGenerateKeypair',
  'curveScalarMultiply',
  'curveSign',
  'curveVerify',
  'protoDecodePkmsg',
  'protoDecodeWhisper',
  'protoEncodePkmsg',
  'protoEncodeWhisper',
  'ratchetDecryptPkmsg',
  'ratchetDecryptWhisper',
  'ratchetEncrypt',
  'sessionDeserialize',
  'sessionHaveOpenSession',
  'sessionSerialize',
  'x3DhBuildInitialSession',
  'x3DhBuildRecipientSession',
];

// napi.config.json declares no wasm target, so the CLI passes an empty flavor
// list and the loader falls back to the single-flavor chain.
const WASI_FLAVORS = [];

const generate = (dir) =>
  writeJsBinding({
    platform: true,
    idents: IDENTS,
    jsBinding: 'index.cjs',
    binaryName,
    packageName: JS_PACKAGE_NAME,
    version,
    outputDir: dir,
    wasiFlavors: WASI_FLAVORS,
  });

const generateInto = async () => {
  const dir = mkdtempSync(join(tmpdir(), 'oktz-signal-generated-'));
  await generate(dir);
  return dir;
};

const runGuard = (args, cwd) => {
  try {
    return { status: 0, stdout: execFileSync(process.execPath, [guard, ...args], { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) };
  } catch (error) {
    return { status: error.status ?? 1, stdout: error.stdout ?? '', stderr: error.stderr ?? '' };
  }
};

const MARKER = /\/\* oktz-signal:hand-maintained:(begin|end) ([a-z0-9-]+) \*\//g;
const delimitedRegions = (source) => {
  const begins = [...source.matchAll(MARKER)].filter((m) => m[1] === 'begin').map((m) => m[2]);
  const ends = [...source.matchAll(MARKER)].filter((m) => m[1] === 'end').map((m) => m[2]);
  return { begins, ends };
};

const reportedRegions = (stderr) =>
  [...stderr.matchAll(/^ {2}- ([a-z0-9-]+):/gm)].map((m) => m[1]);

test('regenerating the loader reproduces the committed loader byte for byte', async () => {
  // The hand-maintained regions have to survive a regeneration, and the only
  // way to know that is to hand the guard a genuine generator output and
  // require the result to be exactly the file that gets published.
  const dir = await generateInto();
  const staged = join(dir, 'index.cjs');
  try {
    const generated = readFileSync(staged, 'utf8');
    assert.notEqual(generated, committed, 'the generated loader is identical to the committed one, so this proves nothing');

    const patched = join(dir, 'patched.cjs');
    const result = runGuard(['patch', staged, patched], dir);
    assert.equal(result.status, 0, `patch refused a real generator output: ${result.stderr}`);
    assert.equal(readFileSync(patched, 'utf8'), committed);
    assert.ok(!existsSync(staged), 'the staging file was not cleaned up, so a failed build would leave it behind');
  } finally {
    rmSync(dir, { force: true, recursive: true });
  }
});

test('the publish guard refuses a regenerated loader', async () => {
  const dir = await generateInto();
  try {
    const result = runGuard(['verify', join(dir, 'index.cjs')], dir);
    assert.notEqual(result.status, 0, 'a regenerated loader passed the publish guard');
    // default-export is what tests/platform-loader.test.mjs:17 asserts
    // (native.default === native); version-check-helpers is the first of the
    // seven hardening fixes.
    assert.match(result.stderr, /- default-export:/, result.stderr);
    assert.match(result.stderr, /- version-check-helpers:/, result.stderr);
  } finally {
    rmSync(dir, { force: true, recursive: true });
  }
});

test('the publish guard accepts the committed loader', () => {
  const result = runGuard(['verify', loaderPath], root);
  assert.equal(result.status, 0, result.stderr);
});

test('the publish guard reports exactly the regions the loader delimits', async () => {
  // A region the guard checks but the file does not mark is invisible to a
  // maintainer, and a marker with no guard behind it is a lie.
  const { begins, ends } = delimitedRegions(committed);
  assert.ok(begins.length > 0, 'the committed loader delimits no hand-maintained region');
  assert.deepEqual([...begins].sort(), [...ends].sort(), 'a hand-maintained region is delimited asymmetrically');
  assert.equal(new Set(begins).size, begins.length, 'a hand-maintained region is delimited twice');

  const dir = await generateInto();
  try {
    const { stderr } = runGuard(['verify', join(dir, 'index.cjs')], dir);
    assert.deepEqual([...reportedRegions(stderr)].sort(), [...begins].sort());
  } finally {
    rmSync(dir, { force: true, recursive: true });
  }
});

const LOST_REGIONS = [
  {
    region: 'default-export',
    line: 'module.exports.default = nativeBinding\n',
  },
  {
    region: 'version-check-helpers',
    line: "const __napiBindingVersionIsStale = (bindingPackageVersion) => bindingPackageVersion !== '0.3.0-rc.1'\n",
  },
  {
    region: 'npm-advice-gating',
    line: '    const unresolvedOnly = loadErrors.every((e) => e && e.code === \'MODULE_NOT_FOUND\')\n',
  },
];

for (const { region, line } of LOST_REGIONS) {
  test(`the publish guard refuses a loader that lost only the ${region} region`, () => {
    // A full regeneration is the loud case. A partial one is the dangerous
    // one: the file still has seven regions' worth of markers, so a guard that
    // only counted regions would pass it.
    assert.ok(committed.includes(line), `fixture is stale: the committed loader no longer contains ${JSON.stringify(line)}`);
    const dir = mkdtempSync(join(tmpdir(), 'oktz-signal-partial-'));
    try {
      const partial = join(dir, 'index.cjs');
      writeFileSync(partial, committed.replace(line, ''));
      const result = runGuard(['verify', partial], dir);
      assert.notEqual(result.status, 0, `a loader missing ${region} passed the publish guard`);
      assert.match(result.stderr, new RegExp(`- ${region}:`), result.stderr);
    } finally {
      rmSync(dir, { force: true, recursive: true });
    }
  });
}

test('the loader patch fails closed when the generator output changes', async () => {
  // An @napi-rs/cli upgrade that moves an anchor must stop the publish, not
  // quietly emit a loader with one fix missing.
  const dir = await generateInto();
  try {
    const staged = join(dir, 'index.cjs');
    const generated = readFileSync(staged, 'utf8');
    const drifted = generated.replace(
      "if (bindingPackageVersion !== '0.3.0-rc.1' && process.env.NAPI_RS_ENFORCE_VERSION_CHECK",
      "if (bindingPackageVersion !== '0.3.0-rc.1' && process.env.SOME_RENAMED_ENFORCEMENT_FLAG",
    );
    assert.notEqual(drifted, generated, 'the drift fixture did not change the generated loader');
    writeFileSync(staged, drifted);

    const patched = join(dir, 'patched.cjs');
    const result = runGuard(['patch', staged, patched], dir);
    assert.notEqual(result.status, 0, 'a drifted generator output was patched anyway');
    assert.ok(!existsSync(patched), 'a failed patch still wrote the published loader');
  } finally {
    rmSync(dir, { force: true, recursive: true });
  }
});

// A publish runs `prepublishOnly`. This drives that script for real, in a
// sandbox, with only the Rust compile stubbed out: `build` is replaced by a
// no-op so the chain under test is the one that can ship a reverted loader --
// the guard step that follows it. If `verify:loader` is ever dropped from
// `prepublishOnly`, both tests below change outcome.
const publishSandbox = (loaderSource) => {
  const dir = mkdtempSync(join(tmpdir(), 'oktz-signal-publish-'));
  cpSync(join(root, 'scripts'), join(dir, 'scripts'), { recursive: true });
  mkdirSync(join(dir, 'native', 'signal'), { recursive: true });
  writeFileSync(join(dir, 'native', 'signal', 'index.cjs'), loaderSource);

  const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  manifest.scripts.build = 'node -e "process.exit(0)"';
  writeFileSync(join(dir, 'package.json'), JSON.stringify(manifest, null, 2));

  try {
    return { status: 0, stdout: execFileSync('npm', ['run', '--silent', 'prepublishOnly'], { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }) };
  } catch (error) {
    return { status: error.status ?? 1, stdout: error.stdout ?? '', stderr: error.stderr ?? '' };
  } finally {
    rmSync(dir, { force: true, recursive: true });
  }
};

test('prepublishOnly refuses to publish a regenerated loader', async () => {
  const dir = await generateInto();
  let regenerated;
  try {
    regenerated = readFileSync(join(dir, 'index.cjs'), 'utf8');
  } finally {
    rmSync(dir, { force: true, recursive: true });
  }
  const result = publishSandbox(regenerated);
  assert.notEqual(result.status, 0, 'prepublishOnly accepted a regenerated loader');
  assert.match(result.stderr + result.stdout, /hand-maintained/, `${result.stdout}${result.stderr}`);
});

test('prepublishOnly accepts the committed loader', () => {
  const result = publishSandbox(committed);
  assert.equal(result.status, 0, result.stderr);
});
