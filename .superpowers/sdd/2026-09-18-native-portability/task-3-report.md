# Task 3 Report: Signal Prebuild CI And Release

## Files Changed

- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `tests/pack-install.test.mjs`

## CI

- Push and pull-request workflow builds GNU, musl, ARM64, and Android napi targets.
- GNU x64 runs full public test suite, platform-loader test, and pack-install test.
- ARM64 Linux and Android report `compile-only`; no runner claims runtime coverage.
- Every target generates and uploads its matching npm platform package artifact.

## Release

- Release workflow starts only on `v*` tags or manual dispatch.
- It rebuilds Linux artifacts, verifies all publish tarballs, publishes Linux platform packages, then publishes main package last with npm provenance.
- Android package is intentionally excluded from release publishing until a real Android runtime test job exists. No manual approval input bypass exists.

## Verification

- `node --test tests/pack-install.test.mjs`: passed.
- `npm test`: passed, 20 tests.
- `node --test tests/platform-loader.test.mjs tests/pack-install.test.mjs`: passed, 3 tests.
- `git diff --check`: passed.

## Limitation

- Local `actionlint` validation unavailable: `npm exec --yes --package=actionlint -- actionlint ...` returned `actionlint: command not found`. GitHub Actions has not run yet.
