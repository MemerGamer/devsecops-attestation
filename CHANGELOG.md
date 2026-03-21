# Changelog

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
