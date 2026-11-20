# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-16

First release on Hex. It's a rewrite of the 2021 proof of concept, which was never published: the
`secure_handle_event` macro and `sign_event/2` / `sign_phx_value/3` are gone. The README's "Changes from the
2021 proof of concept" lists the differences.

### Added

- `on_mount {LiveViewSecure, events: ...}` verifies declared events in an `attach_hook(:handle_event)` that runs
  before `handle_event/3` and before any other `:handle_event` hook, so handlers stay unchanged. `events: :all`
  with `:except` protects every event by default.
- Signing helpers in `LiveViewSecure.HTML`: `signed_attrs/4` for `phx-click` and the other event bindings,
  `signed_push/3` for `JS.push/2`, and `<.signed_inputs>` for hidden form values.
- One HMAC-SHA256 (truncated to 128 bits) over the event name and all of its values, with the signed keys listed
  in the token, so values can't be changed, swapped between elements, added or dropped.
- A random root key per LiveView process, held outside the assigns. There's no secret to configure.
- Per-event policies for params that arrive unsigned (`:unsigned`), params that must always be signed
  (`:signed`), and what a rejection does (`on_failure: :raise | :halt`).
- LiveComponent support with `LiveViewSecure.attach/2`.
- `LiveViewSecure.rotate/1` revokes every token issued so far, and `single_use: true` accepts each rendered token
  for an event once.
- Telemetry events for verification, rejections, unverified events and key rotations, and a default logger,
  `LiveViewSecure.Telemetry.attach_default_logger/1`.
- Misconfigurations raise at mount or render, such as attaching twice to one LiveView, or signing an event that
  isn't declared.
- `SECURITY.md`: the threat model, the design, and the findings of the security review.

### Security

- Requires `phoenix_live_view` 1.1.34, 1.2.14 or later. Earlier releases let a hand-crafted join skip a
  `live_session`'s `on_mount` hooks, LiveViewSecure's included
  ([CVE-2026-126334](https://github.com/phoenixframework/phoenix_live_view/security/advisories/GHSA-v4p7-3pm2-wq6c),
  found during this library's security review).
