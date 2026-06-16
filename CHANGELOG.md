# Changelog

All notable changes to this project are documented here.

This project follows a lightweight release format inspired by Keep a Changelog and uses semantic version tags for public releases.

## [Unreleased]

### Changed

- Hardened Telegram authorization so a configured chat allowlist is required; optional user IDs now act as an additional guard.
- Hardened `quota-gate` so management/dashboard paths are not proxied through the quota gate and unknown `/quota/me` keys return a generic unauthorized response.
- Serialized Telegram quota/key mutations with the shared quota-enforcer lock to protect runtime quota files from cross-process write races.
- Passed `API_PUBLIC_BASE_URL` through the public Compose file so generated API-key messages can use the configured public endpoint.

## [0.1.0] - 2026-06-15

### Added

- Initial open-source release of CLIProxy Telegram Ops.
- Published Docker images for `quota-gate` and `telegram-alerts` on GHCR.
- Portable `compose.public.yaml` for running the public stack from images.
- Telegram alert, operator workflow, quota-management, and change-watch test coverage.
- Public Docker quickstart, security policy, contribution guide, and architecture documentation.

[0.1.0]: https://github.com/kyhoavuong/cliproxy-telegram-ops/releases/tag/v0.1.0
