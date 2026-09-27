// Static assertions on .github/workflows. A workflow cannot be executed from a
// test, so the only way to make "the release runs tests" a regression-proof
// claim is to assert it about the workflow's own shape.
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const { load } = createRequire(import.meta.url)('js-yaml');
const { scripts } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const source = (name) => readFileSync(join(root, '.github', 'workflows', name), 'utf8');
const parse = (name) => load(source(name), { filename: `.github/workflows/${name}` });
const NAMES = ['ci.yml', 'release.yml'];

const steps = (job) => job.steps ?? [];
const runText = (job) => steps(job).map((s) => s.run).filter(Boolean).join('\n');
const needs = (job) => [job.needs ?? []].flat().filter(Boolean);
const RUNS_TESTS = /\b(?:npm run test:all|npm run test:rust|npm test|node --test|cargo test)\b/;

const ancestors = (doc, id, found = new Set()) => {
  for (const parent of needs(doc.jobs[id] ?? {})) {
    if (found.has(parent)) continue;
    found.add(parent);
    ancestors(doc, parent, found);
  }
  return found;
};

const publishSteps = (doc) => Object.entries(doc.jobs).flatMap(([id, job]) =>
  steps(job)
    .filter((s) => /\bnpm publish\b/.test(s.run ?? ''))
    .map((step) => ({ job: id, step })));

test('js-yaml is available to parse workflows', () => {
  // Undeclared transitive dep of @napi-rs/cli. If this ever breaks, declare
  // js-yaml as a devDependency rather than weakening the assertions below.
  assert.equal(typeof load, 'function');
});

test('every workflow is strict-YAML parseable', () => {
  for (const name of NAMES) parse(name);
});

test('every npm publish step is in a job that needs a job which runs the test suite', () => {
  const doc = parse('release.yml');
  const tested = Object.keys(doc.jobs).filter((id) => RUNS_TESTS.test(runText(doc.jobs[id])));
  assert.notDeepEqual(tested, [], 'no job in release.yml runs any test suite at all');

  for (const { job, step } of publishSteps(doc)) {
    const guarded = tested.filter((id) => ancestors(doc, job).has(id));
    assert.notDeepEqual(guarded, [],
      `release.yml job \`${job}\` publishes (\`${step.name ?? step.run}\`) but needs no job that runs tests`);
  }
});

test('release.yml publish job declares needs: verify', () => {
  const doc = parse('release.yml');
  assert.ok(doc.jobs.verify, 'release.yml must define a `verify` job');
  assert.ok(needs(doc.jobs.publish).includes('verify'),
    `release.yml publish must declare \`needs: verify\`, got ${JSON.stringify(needs(doc.jobs.publish))}`);
});

test('release.yml verify job runs the full suite, both cargo and node', () => {
  const verify = parse('release.yml').jobs.verify;
  assert.ok(verify, 'release.yml must define a `verify` job that runs the suite');
  const runs = runText(verify);
  assert.match(runs, /npm run test:all|cargo test[\s\S]*node --test|npm run test:rust[\s\S]*npm test/,
    'release.yml verify must run the whole suite (cargo test + node --test), not one half of it');
});

test('the gated suite includes the real pack, install and import smoke test', () => {
  assert.equal(scripts.test, 'node --test',
    'scripts.test must stay bare `node --test` or the pack/import smoke tests never run in the release gate');
  for (const file of ['pack-install.test.mjs', 'platform-loader.test.mjs']) {
    assert.ok(existsSync(join(root, 'tests', file)), `tests/${file} is the pack/install/import smoke test`);
  }
});

test('no workflow runs node --test with a positional path or glob', () => {
  // `node --test tests/**/*.test.mjs` is Node 22 only; the Node 20 CI leg
  // would silently run zero tests.
  for (const name of NAMES) {
    for (const [, tail] of source(name).matchAll(/node --test([^\n]*)/g)) {
      const [arg] = tail.trim().split(/\s+/);
      assert.ok(arg === undefined || arg.startsWith('-'),
        `${name}: \`node --test${tail}\` passes a positional argument, which Node 20 rejects`);
    }
  }
});
