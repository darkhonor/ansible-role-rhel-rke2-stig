# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- RHEL 10 STIG (V1R1) support via version-gated dataset loading: RHEL 10 audit
  rules, kernel module blacklist, and RHEL 10-gated `all.rp_filter` / IPv6
  forwarding toggles.
- Renovate configuration to keep the Rocky base-image digest current
  (digest-only; the pins Dependabot cannot track). (#36, #40)
- Supply-chain cooldown window for Dependabot updates, standardized with the
  sibling repositories. (#35)
- Dependabot `codeql-action` version-lockstep group, so the `github/codeql-action`
  sub-actions are always proposed as one PR at a single SHA instead of drifting
  apart into a broken analysis.

### Fixed

- Re-pinned the Rocky Linux 9 UBI-init image to a live digest after the pinned
  digest was removed upstream, restoring CI across all branches. (#34)
- Dropped a trailing slash on the RHEL 10 `/etc/sudoers.d` audit path that made
  the rule kernel-unloadable.
- Tolerate missing RKE2 audit watch paths when pre-staging on a golden image.
- Restore the CodeQL workflow by moving `github/codeql-action` `init`,
  `analyze`, and `upload-sarif` to a single release (v4.37.6) in one commit.
  The sub-actions share one monorepo commit and the action fails closed when
  they disagree, so the per-sub-action Dependabot bumps (#50, #51, #53) each
  broke the analysis on their own and could not be fixed by merging them
  individually — they targeted different releases.

### Security

- Set explicit least-privilege `permissions` on all CI and release workflow
  jobs, resolving the CodeQL `actions/missing-workflow-permissions` findings.
- Update `cryptography` to 48.0.1, remediating GHSA-537c-gmf6-5ccf (vulnerable
  OpenSSL bundled in the cryptography wheels). (#43)

### Dependencies

- Bump ansible-core from 2.21.0 to 2.21.1
- Bump ansible-lint from 26.4.0 to 26.6.0 (#31)
- Bump molecule from 26.4.0 to 26.6.0 (#30)
- Bump molecule-plugins from 25.8.12 to 26.7.8 (#33)
- Bump actions/checkout from 6.0.3 to 7.0.0
- Bump actions/setup-python from 6.2.0 to 6.3.0 (#28)
- Bump github/codeql-action from 4.36.1 to 4.36.2
- Bump github/codeql-action/upload-sarif from 4.36.2 to 4.37.0 (#32)
- Bump cryptography from 48.0.0 to 48.0.1 (#43)
- Bump ansible-core from 2.21.1 to 2.21.2 (#47)
- Bump pre-commit from 4.6.0 to 4.6.1 (#48)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#52)
- Bump actions/setup-python from 6.3.0 to 7.0.0 (#54)
- Bump cryptography from 48.0.1 to 50.0.0 (#55)
- Bump github/codeql-action from 4.37.0 to 4.37.6 (`init`, `analyze`,
  `upload-sarif` in lockstep)

## [0.3.2] - 2026-06-04

Maintenance release: STIG baseline refresh and Galaxy namespace alignment. No
changes to role remediation behavior since v0.3.1.

### Changed

- Updated to RHEL 9 STIG V2R8 and RKE2 STIG V2R6 (Container Platform SRG remains
  V2R4).
- Reclassified three FIPS controls (RHEL-09-215105, -255070, -255075) from
  CAT II to CAT I per DISA; severity metadata and docs updated.
- Role namespace updated to `mpe_es` to match the canonical organization repo.

### Fixed

- Corrected RHEL-09-215105 (V-258241): COMPLIANT via FIPS:AD-SUPPORT, removed
  from the STIG exemptions list.

## [0.3.1] - 2026-06-04

Maintenance and supply-chain hardening release. No changes to role behavior
since v0.3.0.

### Changed

- Replaced the Molecule test base with Rocky Linux 9 (ubi-init), removing an
  external-egress dependency and improving STIG fidelity.
- CI Python updated to 3.12 to match ansible-core 2.21.

### Security

- SHA-pin all GitHub Actions; digest-pin the Molecule image; hash-pin the Python
  toolchain (`--require-hashes`); freeze pre-commit hook revisions to SHAs.

### Dependencies

- ansible-core 2.21.0, ansible-lint 26.4.0, molecule 26.4.0,
  molecule-plugins[podman] 25.8.12, yamllint 1.38.0, pre-commit 4.6.0,
  jmespath 1.1.0.

## [0.3.0] - 2026-02-06

### Added

- Kernel hardening sysctl settings; SSH MACs, ClientAlive, pubkey auth, and
  crypto policy; PAM hashing, smart card, and SSSD; file permissions and mail
  relay; NetworkManager DNS; RKE2 operational configs and exemption docs.

### Changed

- Updated STIG baseline to V2R7; made the user-namespace limit configurable.

### Fixed

- Write IP forwarding settings to `/etc/sysctl.conf`; container-tolerant sysctl
  and handler reloads; install `community.general` for the syntax check.

## [0.2.0] - 2026-01-23

### Changed

- Molecule testing moved to UBI9-init with CentOS repos (SCRM-compliant), with
  cgroups v2 fixes for GitHub Actions runners.

### Fixed

- Corrected `PASS_MIN_DAYS` verification logic; made auditd reload
  container-aware.

## [0.1.0] - 2026-01-23

### Added

- Initial RHEL 9 / RKE2 STIG remediation role: baseline controls, Molecule +
  Podman CI, pre-commit hooks, and pinned Python requirements.

[Unreleased]: https://github.com/mpe-es/ansible-role-rhel-rke2-stig/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/mpe-es/ansible-role-rhel-rke2-stig/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/mpe-es/ansible-role-rhel-rke2-stig/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mpe-es/ansible-role-rhel-rke2-stig/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mpe-es/ansible-role-rhel-rke2-stig/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mpe-es/ansible-role-rhel-rke2-stig/releases/tag/v0.1.0
