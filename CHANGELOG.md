# Changelog

All notable changes to this project are documented here.

This project follows a lightweight release format inspired by Keep a Changelog and uses semantic version tags for public releases.

## [Unreleased]

### Changed

- Updated portable examples to CLIProxyAPI v7.2.47.
- Updated portable examples to CPA Usage Keeper v1.12.2.

## [0.2.6] - 2026-06-24

### Changed

- Updated portable examples to CLIProxyAPI v7.2.33-amd64 and CPA Usage Keeper v1.12.0.

### Fixed

- Bound Telegram key disable/enable/delete confirmations to the scoped chat, user, action type, target key fingerprint, and pending action timestamp.
- Cleared stale key-management confirmations when operators reopen key workflows, preventing old Confirm buttons from mutating the wrong key later.
- Recorded secret-safe operator attribution and key fingerprints in action audit entries.

## [0.2.5] - 2026-06-19

### Changed

- Published the v0.2.5 public helper image tags.
- Updated portable examples to CLIProxyAPI v7.2.22.

## [0.2.4] - 2026-06-19

### Changed

- Published the v0.2.4 public helper image tags.

### Fixed

- Added post-mutation verification warnings for Telegram key/quota actions while keeping successful replies unchanged.
- Normalized provider labels for Codex, Antigravity, and unknown proxy-account notifications.
- Kept manually disabled keys visible in the Usage Keeper registry without reactivating them in proxy config.

## [0.2.3] - 2026-06-19

### Changed

- Updated the portable stack to CLIProxyAPI v7.2.19 and CPA Usage Keeper v1.11.1.
- Standardized recovery notifications to use `[RESOLVED]` and clearer service health alert templates.

### Fixed

- Kept manually disabled keys disabled across quota-enforcer, CPA registry sync, and change-watch reconciliation.
- Prevented stale manual-disable markers from emitting false key enabled or key created notifications.
- Preserved manually disabled CPA rows instead of reactivating or recreating them during sync.
- Tuned quota inspection compatibility with newer Usage Keeper responses that include inactive or unknown rows.

## [0.2.2] - 2026-06-17

### Fixed

- Hardened CPA tombstone recovery so quota-disabled keys are not mistaken for manual deletes during reset windows.
- Stopped quota-enforcer from recreating missing quota rows from proxy config as unlimited/default rows.
- Added regression guards so quota-enforcer tests fail before writing real runtime quota, state, or proxy config files.
- Preserved true manual delete notifications after protected quota-disabled tombstones have been restored.

## [0.2.1] - 2026-06-16

### Changed

- Hardened Telegram authorization so a configured chat allowlist is required; optional user IDs now act as an additional guard.
- Hardened `quota-gate` so management/dashboard paths are not proxied through the quota gate and unknown `/quota/me` keys return a generic unauthorized response.
- Serialized Telegram quota/key mutations with the shared quota-enforcer lock to protect runtime quota files from cross-process write races.
- Passed `API_PUBLIC_BASE_URL` through the public Compose file so generated API-key messages can use the configured public endpoint.
- Labeled auth-account add/remove notifications by provider, for example `Codex account added` or `Antigravity account added`, while still grouping multiple accounts from the same provider.

## [0.2.0] - 2026-06-15

### Changed

- Synced the latest Telegram operator workflows and quota-enforcer behavior from the production operations repo.
- Added Edu/Team-compatible GPT pool capacity handling while alerting only on true Free/non-Plus quota evidence.
- Hardened manual API-key lifecycle handling so stale manual-disabled markers do not create false Enable options, duplicate notifications, or unsafe CPA pruning.
- Kept bot-confirmed key/quota notifications verified against observed state changes while preserving fast operator feedback.
- Improved public portability with generic defaults, configurable API public base URL, and sanitized test fixtures.

## [0.1.0] - 2026-06-15

### Added

- Initial open-source release of CLIProxy Telegram Ops.
- Published Docker images for `quota-gate` and `telegram-alerts` on GHCR.
- Portable `compose.public.yaml` for running the public stack from images.
- Telegram alert, operator workflow, quota-management, and change-watch test coverage.
- Public Docker quickstart, security policy, contribution guide, and architecture documentation.

[Unreleased]: https://github.com/kyhoavuong/cliproxy-telegram-ops/compare/v0.2.6...HEAD
[0.2.6]: https://github.com/kyhoavuong/cliproxy-telegram-ops/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/kyhoavuong/cliproxy-telegram-ops/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/kyhoavuong/cliproxy-telegram-ops/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/kyhoavuong/cliproxy-telegram-ops/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/kyhoavuong/cliproxy-telegram-ops/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/kyhoavuong/cliproxy-telegram-ops/releases/tag/v0.2.1
[0.2.0]: https://github.com/kyhoavuong/cliproxy-telegram-ops/releases/tag/v0.2.0
[0.1.0]: https://github.com/kyhoavuong/cliproxy-telegram-ops/releases/tag/v0.1.0
