# Changelog

## Unreleased

- Bundle kill switch: an optional boolean `disabled`; when true every request passes through untouched (no rules, cookies, challenge, `X-RG-Sig` or verify call).

## 0.1.0

- Opt-in `X-RG-Sig` signed header (`sig_secret` / `sigSecret`), matching the JS and OpenResty ports.

- First release under the MIT licence. Hostname canonicalization, punycode and strict JSON reading are the
  `revokegpt/revokegpt` SDK's (pinned to the exact version, `0.1.0`) instead of copies.
