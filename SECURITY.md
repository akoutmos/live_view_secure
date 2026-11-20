# Security

## Threat model

**The attacker** is a user of your app with a valid session. They fully
control their own browser and websocket: they can send any event, with any
params, event type, component target, join message or frame order, and read
everything rendered to them.

**Their goal** is to make a declared event's handler run with params this
LiveView did not render for them. That covers changed, swapped, added or
removed values, events copied from another tab or user, and events whose
button has been revoked.

**Out of scope:**
* code running on the server node, which can read any process's memory;
* XSS in your app, since injected script can click your real buttons;
* your authorization logic;
* inputs that aren't events: URL params in `handle_params/3`, upload progress
  callbacks.

## Guarantees

For every declared event, the handler runs only if all of these hold:

* the event name and every signed value were rendered together on one element
  by this LiveView (or LiveComponent) process;
* the token was issued under the context's current key, and isn't a used
  `single_use` token;
* no signed param was removed;
* no unsigned param was added beyond what the event's `:unsigned` policy
  allows, and the browser's empty DOM `value` (`""` or `0`);
* no param listed in `:signed` arrived unsigned.

Verification runs before `handle_event/3` and before every other
`:handle_event` hook. Configurations that would silently skip it raise when
the LiveView mounts or renders. That includes signing an undeclared event, and
signing a key the policy also accepts unsigned, and attaching twice to one
LiveView.

The hook has to run for that, so LiveViewSecure requires LiveView 1.1.34,
1.2.14 or later. Earlier releases let a hand-crafted join skip a
`live_session`'s `on_mount` hooks (see [Upstream LiveView
issue](#upstream-liveview-issue)). A `live_session` declaration covers only
the LiveViews mounted through that session's routes, so the README recommends
declaring `on_mount` in the LiveView module.

A signature proves "this was on the page", not "this user may do it now". Keep
authorizing in your contexts. See the README's "Known limitations" for what
the library can't enforce.

## Design summary

* **Token:** `"<sorted keys>.<base64url(HMAC-SHA256 truncated to 128 bits)>"`
  over a domain tag and length-prefixed (64-bit) fields:
  `event`, key count, then each key and value.
  * Only the canonical base64 spelling is accepted.
  * Tokens over 4 KB and key lists over 32 keys are rejected before any MAC
    work.
* **Keys:**
  * Each LiveView process has a 256-bit root key from
    `:crypto.strong_rand_bytes/1`. It's held in an `:atomics` array referenced
    from the process dictionary.
  * Each context (a LiveView or LiveComponent) has a random 128-bit id, and
    signs with `HMAC(root, domain <> id)`.
  * No key material is ever in an assign, a struct, a log or a message.
  * Using a context outside its owning process raises.
* **Single use:** accepted pairs are counted. Pair *n* is signed with
  `HMAC(key, use_domain, base_mac, n)`, so only the used element's token
  changes.
* **Rotation:**
  * `rotate/1` on a LiveView replaces the root, which revokes the LiveView and
    all its components. On a component it replaces that component's id.
  * Tokens from exactly one generation back are recognized as `:revoked`, and
    only for an otherwise untampered payload. They're dropped, never raised.
* **Comparison:** MACs are compared with `Plug.Crypto.secure_compare/2`. Early
  returns depend only on the payload's structure, never on the key.

## Security review

On 2026-11-16 the library went through a thorough security review, made with
AI tools and reviewed by the maintainer. It ran in two adversarial rounds over
four attack surfaces, and every finding was proved with a failing test before
it was fixed. The surfaces were:

* token cryptography and parsing;
* the LiveView wire protocol, driven over a real Bandit endpoint with raw V2
  JSON websocket frames;
* lifecycle, rotation and replay;
* developer misuse, output safety and key leakage.

### Findings

| Severity | Finding | Status |
| --- | --- | --- |
| High | A live_session-level `on_mount` is skipped by a hand-crafted join without `"url"`, so nothing is verified | Fixed upstream in LiveView 1.1.34 and 1.2.14 ([CVE-2026-126334](https://github.com/phoenixframework/phoenix_live_view/security/advisories/GHSA-v4p7-3pm2-wq6c)), which LiveViewSecure requires. See [Upstream LiveView issue](#upstream-liveview-issue) |
| High | An event a template signs but `:events` doesn't declare is accepted unsigned | Fixed: helpers raise at render; undeclared signed events, and signed events reaching hook-less sockets, are reported (and logged by the default logger) |
| Medium | Under `unsigned: :allow`, a token covering fewer keys lets the client supply the rest (e.g. `id`) | Fixed: `:signed` is required with `:allow`; signing a key the policy also accepts unsigned raises at render |
| Medium | `rotate/1` on a LiveView didn't revoke its components' tokens | Fixed: per-process root key |
| Medium | Tokens are replayable until rotation | Mitigated: per-pair `single_use`; documented |
| Medium | `single_use` (first version) killed every other token, including stream items | Fixed: per-pair use counts |
| Medium | `attach/2` called from a live_session wrapper is skipped by a url-less join | Fixed upstream, with the High finding above |
| Medium | Key reachable via a nested LiveView's session token (signed, not encrypted) | Fixed: no key material in the struct |
| Medium | A component signing with its parent's context is never verified | Partial: caught at render with `target:`; otherwise logged; documented |
| Medium | `:handle_event` hooks attached earlier (e.g. by a live_session) ran before verification | Fixed: verification hook moved to the front |
| Low | `assign_new`/session handing a context to a nested LiveView let it mint parent tokens | Fixed: contexts are bound to their process and component |
| Low | A parent context passed into a component replaced the component's key | Fixed: `:foreign_context` |
| Low | A revoked token carrying injected params was reported as a benign `:revoked` | Fixed |
| Low | `events: [:all]` silently meant an event named "all"; duplicate declarations silently overrode | Fixed: both forms now work as intended, or raise |
| Low | Nested names like `"post[id]"` in `:signed` protected nothing | Fixed: raise |
| Low | JS-command-shaped event names and arbitrary `:binding` attributes | Fixed: validated; bindings allowlisted |
| Low | CR/NUL values and `<li>` clicks (`value` 0) never verified; `nil`/`false` became truthy strings | Fixed |
| Low | In-flight clicks during rotation crashed the LiveView; stale components never recovered | Fixed |
| Low | Key shown by `inspect(structs: false)` and `~p` | Fixed |
| Info | Unbounded client-chosen strings in logs and errors; 32-bit length prefixes | Fixed |

What was tried and blocked includes:

* **Forgery and collisions:** 20k random MACs, and keys derived the wrong way;
  property tests that re-split the same bytes into different
  events/keys/values; every single-byte substitution, insertion and deletion
  in a token; alternative base64 spellings.
* **Timing:** median verify time is the same whether the MAC differs in its
  first or last byte.
* **Wire shapes:**
  * every event type, `value` as a string, list, null or number, and
    urlencoded form tricks (duplicate, nested and NUL keys);
  * `cid` retargeting and look-alike event names;
  * events pipelined behind the join, rewritten joins, and pipelined
    single-use replays.
* **Key leakage:** no key bytes in `inspect`, `~p`, `term_to_binary`,
  `:sys.get_state`, the process dictionary, crash logs, telemetry or session
  tokens.
* **Denial of service:** verification cost measured linear up to 100 MB
  values and 1M params.

The suite has 13 properties and 323 tests. During the review, each of 16
targeted mutations of the library failed at least one test.

### Upstream LiveView issue

The first High finding came from LiveView itself (verified on 1.2.13). A
hand-crafted join that left out `"url"` mounted a routed LiveView without its
`live_session`'s `on_mount` hooks: LiveViewSecure's, and any of the app's own,
such as authentication. It was reported privately to the Phoenix team, who
fixed it in LiveView 1.0.20, 1.1.34 and 1.2.14. See their advisory,
[CVE-2026-126334 (GHSA-v4p7-3pm2-wq6c)](https://github.com/phoenixframework/phoenix_live_view/security/advisories/GHSA-v4p7-3pm2-wq6c).

Until the fix was released, LiveViewSecure worked around it by requiring
`on_mount` in the LiveView module, since a module's own hooks ran on every
join. It now requires a fixed LiveView instead, and the tests that replay the
attack fail on 1.2.13. If your app uses `live_session` hooks for anything, run
a fixed LiveView whether or not you use LiveViewSecure.

## Reporting a vulnerability

Please report vulnerabilities privately through a GitHub security advisory on
this repository, not as a public issue.
