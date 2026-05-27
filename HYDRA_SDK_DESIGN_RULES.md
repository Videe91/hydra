# Hydra SDK — Design Rules

*Immutable. Read this before touching any SDK code in any language.*

The SDK is the membrane between AI systems and the living database. It is not an "API client." It is the agent-facing surface of Hydra's semantics. These rules exist so the SDK doesn't drift into either a thin REST wrapper (loses meaning) or a fat application framework (loses neutrality) as it grows across languages.

---

## 1. Semantic methods, not endpoint mirrors

SDK methods name **operations** in Hydra's living-database vocabulary, not HTTP routes.

```python
# YES
await hy.propose_claim(subject=..., predicate="is_stale", ...)

# NO
await hy.post("/ingest", json={"event_kind": "ClaimProposed", ...})
```

If a method name reads like an HTTP path, rename it. If a route can serve two semantic operations, the SDK exposes two methods. The wire format is an implementation detail.

---

## 2. Transport DTOs mirror the wire format exactly

Response and request types in the SDK match Hydra's JSON wire format **byte-for-byte** in field names, casing, optionality, and discriminator shape. No alternate naming. No flattening. No re-nesting.

Operators reading the JSON and operators reading the Python see the same thing. This makes server logs and client code mutually grep-able.

---

## 3. Async-first, always

Every public method is `async def`. Sync variants exist as mechanical mirrors (same name + `_sync` suffix, same args, same return shape) generated from the async definitions. The SDK is built for agent runtimes (FastAPI, LangGraph, autonomous loops), all of which are async.

A sync-only environment (script, Jupyter cell) uses the `_sync` mirror. No method ships sync-only.

---

## 4. All public methods are fully typed

Every argument has a type annotation. Every return value has a type annotation. Every public class has a complete type signature. `mypy --strict` passes.

This is non-negotiable because LLM tool-call wrappers (LangChain, OpenAI structured outputs, MCP) infer call schemas from type hints. An untyped SDK is a broken agent SDK.

---

## 5. No hidden retries in v0

If a request fails, the exception surfaces. The SDK does not retry transparently, does not implement exponential backoff, does not silently re-route. The caller (or their orchestration layer) decides retry policy.

Hydra's puller has retry logic because it's a long-running worker. The SDK is a request-response client. The two are different roles.

---

## 6. No local caching

The SDK does not cache responses. Every call hits Hydra. The engine is the source of truth; caching invites staleness bugs and breaks the "is this anomalous right now?" semantics.

Caching is a deployment concern (reverse proxy, CDN, application-layer cache), not an SDK concern.

---

## 7. Tenant override always available on every endpoint

Every method that hits a tenant-scoped route accepts `tenant: str | None = None`, defaulting to the client's configured tenant. Passing `tenant=` per call overrides the default for that one call.

Multi-tenant agent code routinely flips tenant per request. The SDK supports this without forcing a new client instance.

---

## 8. Server errors preserved verbatim

When Hydra returns an error body, the SDK exception carries the raw body, the HTTP status code, and the URL. No re-wrapping, no message reformatting, no field renaming.

```python
except HydraValidationError as e:
    e.status_code  # 400
    e.body         # {"error": "..."}  — verbatim
    e.url          # "http://.../ingest"
```

Operators reading agent logs see exactly what Hydra reported. Agents reasoning over errors see exactly what Hydra reported. No detective work.

---

## 9. No raw HTTP escape hatch in the public API

The SDK does not expose `client.get()` / `client.post()` as public methods. If a user finds themselves wanting raw HTTP, the SDK is missing a semantic method — file an issue, don't paper over.

A private `_http` is fine for tests and SDK internals. It does not appear in `__init__.py` exports.

---

## 10. One client class per Hydra connection

`Hydra(base_url=..., token=..., tenant=...)` is the entry point. There is exactly one. No factory pattern, no builder chain, no global singleton, no auto-configure-from-env (env reading happens in user code, not in the SDK).

Connection pooling and reuse happen inside the one client via `httpx` defaults. Closing the client is `await hy.aclose()`.

---

## 11. Backward compatibility is a load-bearing promise

Once a method signature is in a released SDK, it does not change. New optional arguments append to the end. Removed methods get deprecation warnings for at least one minor version before deletion. Renames are not done — add the new name, keep the old one.

The SDK is consumed by agents that may run in production for years without updates. Breakage is a betrayal.

---

## 12. Errors are typed, not stringly-typed

The exception hierarchy is the API. Callers should be able to write `except HydraReadOnlyFollowerError:` and have it fire on exactly that case. No catching `HydraError` and `.startswith("follower")`-parsing the message.

If a new error category emerges, it gets its own exception class. Status-code-only categorization is a fallback, not a strategy.

---

*These rules are immutable. They are also the only rules. Anything not on this list is a judgment call, made on the patch.*
