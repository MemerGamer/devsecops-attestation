# Changelog

## [0.4.0](https://github.com/MemerGamer/devsecops-attestation/compare/v0.3.2...v0.4.0) (2026-09-21)


### ⚠ BREAKING CHANGES

* attest --fail-on, attest normalize --fail-on, and the bundled deploy.rego policy now default to "high" instead of "critical". Operators pinning --config-hash must recompute it, and any pipeline relying on the previous critical-only default must now pass --fail-on-severity critical explicitly to keep prior behavior.
* signed results must use canonical lowercase severities (info, low, medium, high, critical); non-canonical severities are rejected at signing and deny at the gate. Use --tool-format or attest normalize to convert raw scanner output.

### Features

* accept signing key from file or environment in attest ([83ea084](https://github.com/MemerGamer/devsecops-attestation/commit/83ea08403cece61adb5a22f7283b906006b54e53))
* add normalize, tools and sign subcommands to attest ([6cd415d](https://github.com/MemerGamer/devsecops-attestation/commit/6cd415da38a01a28b135463c99b857e1ecf31b48))
* add reusable composite actions for setup, signing and gating ([4b2a289](https://github.com/MemerGamer/devsecops-attestation/commit/4b2a289d9833bd6a9e2b3004944807b899f3e0a4))
* add tool-output normalizers and open check types ([c37f78b](https://github.com/MemerGamer/devsecops-attestation/commit/c37f78bb1c6220b9405e9041b0b383be1a4c8163))
* bind attestation chains and the gate to a target commit ([2603cef](https://github.com/MemerGamer/devsecops-attestation/commit/2603cef713eec6f8fb7ad443bc2d6f8fe3ddbf13))
* canonical parameterized deploy policy with config pinning ([5cde56d](https://github.com/MemerGamer/devsecops-attestation/commit/5cde56dbb741ce1df133f5b0595029579fd8e567))
* commit binding and pinned signer identity in actions ([b9b6bfc](https://github.com/MemerGamer/devsecops-attestation/commit/b9b6bfc9fcf4e68357c9c05cc67e65da92864faa))
* generalize attestation pipeline (normalizers, open check types, canonical policy) ([88d305a](https://github.com/MemerGamer/devsecops-attestation/commit/88d305ad6c8286702acc7cfcd73564bac0ed9293))
* require secret scan and zero-tolerance for its findings in deploy gate ([1c43a6d](https://github.com/MemerGamer/devsecops-attestation/commit/1c43a6dcceec7bbbc578ea279a7c29eff3a6a5f5))
* reusable composite actions, dogfooded pipeline and integration docs ([5dcdcaf](https://github.com/MemerGamer/devsecops-attestation/commit/5dcdcafca1874050ddea22093f4a62aca02d5d2a))
* seal attestation chains against undeclared check types ([9735d6e](https://github.com/MemerGamer/devsecops-attestation/commit/9735d6ec9400be62eeeb7de577544e730f394199))


### Bug Fixes

* accept current semgrep severities and warn-level scan errors ([1ce4310](https://github.com/MemerGamer/devsecops-attestation/commit/1ce43101eb7a7a7bed0e369786a4753eb345f46b))
* attest command name, quiet usage and help text ([9a56438](https://github.com/MemerGamer/devsecops-attestation/commit/9a56438b3f42e89bfaa47d5dd6663f41a2dcd371))
* catch exact and Unicode-fold duplicate keys in report normalization ([8246e4b](https://github.com/MemerGamer/devsecops-attestation/commit/8246e4b0c519b5099188cb15a8250175110e32f9))
* close fail-open paths in normalizer adapters ([bc8a86a](https://github.com/MemerGamer/devsecops-attestation/commit/bc8a86a3d6654a003025efab83a74b2cf683bc11))
* default blocking threshold to high ([7f1490d](https://github.com/MemerGamer/devsecops-attestation/commit/7f1490d3c4ebfc88a957cb30531e7a69623f606b))
* **deps:** bump golang.org/x/crypto to v0.57.0 ([b212f66](https://github.com/MemerGamer/devsecops-attestation/commit/b212f6660a3f4643c22a06d8cbf44a1d5cd10d0d))
* goreleaser image context, syft install and cosign bundle signing ([6327bde](https://github.com/MemerGamer/devsecops-attestation/commit/6327bdebff221649eb5910941075b64089fb29ba))
* pipeline scanner flags, sigstore bundle verification and doc refs ([42283bc](https://github.com/MemerGamer/devsecops-attestation/commit/42283bce383001db06533d047064442fb5995cd6))
* remove expression from gate action input description ([1fac501](https://github.com/MemerGamer/devsecops-attestation/commit/1fac501e25a10641be778a7a9f21f40ee90a8d2f))
* tolerate checkov parsing errors in frameworks with no resources ([6a83522](https://github.com/MemerGamer/devsecops-attestation/commit/6a83522dce004c864e3b71bb81305ca47e4b651e))


### CI/CD

* close fail-open gaps and harden the interim pipeline workflow ([90298ea](https://github.com/MemerGamer/devsecops-attestation/commit/90298ea0b6915d9581fe9f0c3ff4e7e6074975db))
* dogfood composite actions and pin scanners ([b121f89](https://github.com/MemerGamer/devsecops-attestation/commit/b121f89d86a63da8e82b21839dc7aa3ca64fb770))
* harden scanner steps against report substitution ([8babd3d](https://github.com/MemerGamer/devsecops-attestation/commit/8babd3d10ef6ede867b3d8e5a366637186939031))
* normalize interim pipeline results with attest and pin semgrep ([bf0ae18](https://github.com/MemerGamer/devsecops-attestation/commit/bf0ae18605141ca7d2a0a5c05ede2dcb2de8d51f))


### Documentation

* add integration guide and update architecture for reusable pipeline ([d9629a4](https://github.com/MemerGamer/devsecops-attestation/commit/d9629a48c6be1767a904be27a4c194798c04838e))
* clarify log entry and signer_id guarantees ([6e8392b](https://github.com/MemerGamer/devsecops-attestation/commit/6e8392b9304544d66277ab0d3c07a98bb25e62a3))
* document canonical severity requirement ([c76b26f](https://github.com/MemerGamer/devsecops-attestation/commit/c76b26f47e9cfac4233833fcfba88474d7c4a110))
* fix stale severity defaults, undeclared check types, and pin drift ([0c24e18](https://github.com/MemerGamer/devsecops-attestation/commit/0c24e1831e8c83c7160603f435e3bc6734ce8e37))


### Tests

* make signer-id test independent of CI environment ([e927e71](https://github.com/MemerGamer/devsecops-attestation/commit/e927e712149d1a41c666ab8c1b93d177dcb12db1))

## [0.3.2](https://github.com/MemerGamer/devsecops-attestation/compare/v0.3.1...v0.3.2) (2026-07-10)


### Tests

* add evaluation benchmark and security-efficacy suite ([3d12154](https://github.com/MemerGamer/devsecops-attestation/commit/3d1215419e648e403d3a69e06f91dcf346384b69))
* add evaluation benchmark and security-efficacy suite ([9559fcb](https://github.com/MemerGamer/devsecops-attestation/commit/9559fcb83de1084e8cd1b19366d2fb24db22f222))

## [0.3.1](https://github.com/MemerGamer/devsecops-attestation/compare/v0.3.0...v0.3.1) (2026-05-10)


### Bug Fixes

* handle OPA rego.v1 deny_reasons returned as []interface{} ([cc8250f](https://github.com/MemerGamer/devsecops-attestation/commit/cc8250f2cf128d3cae30a6e31838acc6a9d568ae))

## [0.3.0](https://github.com/MemerGamer/devsecops-attestation/compare/v0.2.1...v0.3.0) (2026-05-10)


### Features

* implement zero-trust compliance improvements ([cf0c09f](https://github.com/MemerGamer/devsecops-attestation/commit/cf0c09f8b0039f8716da8380e05fc9d66a403abb))


### Documentation

* update architecture SVG for zero-trust design ([5d4bdc2](https://github.com/MemerGamer/devsecops-attestation/commit/5d4bdc2d9a68e3411fbf04850d265912992e78e8))
* update documentation to reflect zero-trust architecture ([12b099c](https://github.com/MemerGamer/devsecops-attestation/commit/12b099c21b16c8f24dec6bba767eecd0f2f1a2f6))

## [0.2.1](https://github.com/MemerGamer/devsecops-attestation/compare/v0.2.0...v0.2.1) (2026-03-21)


### CI/CD

* add dependabot auto-merge workflow for patch and minor updates ([8d5fab8](https://github.com/MemerGamer/devsecops-attestation/commit/8d5fab8e498d4e54dd90987e8fd9e1fb0182964c))


### Code Refactoring

* enhanced test coverage and error handling in CLI commands ([cd75472](https://github.com/MemerGamer/devsecops-attestation/commit/cd75472713902e0c3a9bfb9e3d4a552fb6c19791))

## [0.2.0](https://github.com/MemerGamer/devsecops-attestation/compare/v0.1.0...v0.2.0) (2026-03-21)


### Features

* add attestation chain building and verification with full unit tests ([ccd4b46](https://github.com/MemerGamer/devsecops-attestation/commit/ccd4b4632b7200238f4f26eb9a6811a7881aa6c3))
* add Ed25519 signing, verification, and digest with full unit tests ([7e1fc1d](https://github.com/MemerGamer/devsecops-attestation/commit/7e1fc1dbc4dd91523413e5237cba07ef1be1209e))
* add OPA policy evaluator with table-driven tests for allow and deny cases ([bb2e80b](https://github.com/MemerGamer/devsecops-attestation/commit/bb2e80b3ed5f45510310ff8b8dc1f4b4f4bb53d6))
* implement keygen, sign, verify, and gate CLI binaries ([6bb2cb3](https://github.com/MemerGamer/devsecops-attestation/commit/6bb2cb3e37b935b622c21dd3fbec33cc5ad467f8))
* implement simple multisig threshold attestation (t-of-n Ed25519) ([a359d9d](https://github.com/MemerGamer/devsecops-attestation/commit/a359d9dc73f00550d2c3c083d5f0b626d31b916e))


### Bug Fixes

* repair CI pipeline and add provenance, coverage, and dev docs ([7ffa1f3](https://github.com/MemerGamer/devsecops-attestation/commit/7ffa1f33aa89749311b59ebcad757d3b547458fa))


### CI/CD

* add Codecov upload to test job ([caf134a](https://github.com/MemerGamer/devsecops-attestation/commit/caf134afe6146907209154eb214f2fee7aad4752))
* add complete GitHub Actions workflow with attested pipeline ([c5341ff](https://github.com/MemerGamer/devsecops-attestation/commit/c5341ffbe656dcba526545d3d0a5c2addc99075e))
* add test job as prerequisite to security-checks ([4c632b9](https://github.com/MemerGamer/devsecops-attestation/commit/4c632b96888e5e702b7dd7da88cbdabf61101ff9))
* fix trivy install failure and harden all tool steps ([9c713e3](https://github.com/MemerGamer/devsecops-attestation/commit/9c713e384f0f116c4d23deb4463ba3553fb96684))
* implement real security tools and upgrade to Node.js 24 actions ([af609b2](https://github.com/MemerGamer/devsecops-attestation/commit/af609b25af90347895aeb54b3019874118c75c0f))
* opt into Node.js 24 for GitHub Actions ahead of June 2026 migration ([1e3c0fb](https://github.com/MemerGamer/devsecops-attestation/commit/1e3c0fb8013137c58f62e95f3e9f5b2b3b158b74))


### Documentation

* add GitHub Actions setup section with secret configuration steps ([b06852e](https://github.com/MemerGamer/devsecops-attestation/commit/b06852eb9c02bbdaa563bd1bcb2a65a7b5d2eaa4))
* fix Quick Start to sign all three checks and add sample result files ([732934b](https://github.com/MemerGamer/devsecops-attestation/commit/732934b582e721f61d53d5e9d0fd01e6c5f59149))
* split README into docs/ directory and add MIT LICENSE ([47ead36](https://github.com/MemerGamer/devsecops-attestation/commit/47ead36c9daa6c304b83a13869695f401002acfa))
* update README to include DevSecOps pipeline badge ([58c6048](https://github.com/MemerGamer/devsecops-attestation/commit/58c6048cbd84cbdf95dfa44097c761f9e2dc0559))
* update README to reflect completed implementation ([32e11b1](https://github.com/MemerGamer/devsecops-attestation/commit/32e11b144eff609b7c3b1a3eeaa06099b97b5d98))
* update README to standardize code block syntax ([b16a406](https://github.com/MemerGamer/devsecops-attestation/commit/b16a406021af650461f6b45fabca54a3687d38f6))


### Tests

* add integration tests for full pipeline simulation ([d4ca318](https://github.com/MemerGamer/devsecops-attestation/commit/d4ca318dcf9c92fd4fc50596164f5099558000c3))
