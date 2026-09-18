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
- Android package is built and available as artifact, but publish is conditional on `inputs.termux_test_passed == 'true'`. Default is `false`, so Android does NOT publish by default. No manual approval bypass beyond this boolean input.

## Fixes Applied

- Added `workflow_dispatch` with boolean input `termux_test_passed` to CI workflow.
- Added Android target to release workflow `build-linux` matrix.
- Added Android artifact download step in release publish job.
- Added conditional Android publish step `if: ${{ inputs.termux_test_passed == 'true' }}` publishing `@oktz-signal/signal-android-arm64`.
- Preserved existing 4-Linux publish order (x64-gnu, x64-musl, arm64-gnu, arm64-musl) before main package.

## Verification

- `node --test tests/pack-install.test.mjs`: passed.
- `npm test`: passed, 20 tests.
- `node --test tests/platform-loader.test.mjs tests/pack-install.test.mjs`: passed, 3 tests.
- `git diff --check`: passed.

## Limitation

- Local `actionlint` validation unavailable: `npm exec --yes --package=actionlint -- actionlint ...` returned `actionlint: command not found`. GitHub Actions has not run yet.
