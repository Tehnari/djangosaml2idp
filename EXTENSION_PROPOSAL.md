# djangosaml2idp (Tehnari variant) – Add/Update/Extend proposal plan

**Revision:** 1  
**Date:** 2026-02-24  
**Variant version:** 0.7.2+tehnari1  
**Status:** Proposal (not yet implemented)

---

## 1. Current capabilities (summary)

- **SSO:** SP-initiated (POST + Redirect), IdP-initiated (`/sso/init/`).
- **SLO:** Single Logout (POST + Redirect).
- **Metadata:** Dynamic IdP metadata; DB-backed SP config with optional remote metadata URL and fallback expiration.
- **Processors:** `has_access`, `create_identity`, `get_user_id`, optional multifactor hook.
- **NameID:** Unspecified, Persistent, Email; PersistentId model.
- **Resilience:** Compression/deflate fix in `repr_saml`; session + cache + state UUID for cross-site redirects; metadata `validUntil` fallback.
- **Customization:** Custom error view, custom processor, attribute mapping, per-SP nameid_field and signing/encryption.

---

## 2. Bindings (from existing TODOs)

- **SOAP / PAOS**  
  - Code has: "future TODO: parse also SOAP and PAOS format from POST"; SLO has "TODO: SOAP".  
  - **Proposal:** Implement SOAP binding for SLO only if a concrete SP requires back-channel logout. POST/Redirect SLO is sufficient for many deployments.

---

## 3. NameID formats

- **Current:** Unspecified, Persistent, Email; `get_nameid_transient` raises `NotImplementedError`; X509, Kerberos, Entity, Encrypted unmapped (TODO in `processors.py`).  
- **Proposal:**  
  - **Transient (high priority):** Implement as short-lived, SP-specific opaque ID (e.g. cache or small model keyed by (user, sp_entity_id) with TTL). Many SPs expect Transient.  
  - **X509 / Kerberos / Entity / Encrypted:** Implement only if a concrete SP requires them.

---

## 4. Security hardening

- **Request validity window:** Reject `AuthnRequest` if `IssueInstant` is too old (e.g. 5 minutes) to reduce replay risk.  
- **Audience / destination:** Ensure response is sent only to the SP that issued the request; document or reinforce if pysaml2 already enforces.  
- **Signature:** Optional per-SP or global "require signed authn requests".  
- **Error view:** Ensure error page never renders raw exception or user input in production (generic message + server-side logging).

---

## 5. Audit and observability

- **Audit log:** Log successful (and optionally failed) SSO/SLO: timestamp, user id (or NameID), SP entity_id, binding, IP. Store in DB or structured logs.  
- **Metrics:** Optional counters for SSO/SLO success/failure per SP for monitoring.  
- **Health endpoint:** Lightweight `/idp/health/` that checks IdP config load and optionally SP metadata freshness.

---

## 6. SP metadata lifecycle

- **Auto-refresh:** Management command or scheduled job to refresh all SPs with `remote_metadata_url` so long-lived instances stay up to date.  
- **Validation:** On save/refresh, validate metadata (entityID, ACS URLs, certs) and surface errors in admin or logs.

---

## 7. Authn context (optional)

- **Current:** `get_authn()` uses a simple AuthnBroker with PASSWORD.  
- **Proposal:** If step-up is needed, support configurable authn context (e.g. password + MFA) and map `RequestedAuthnContext` from the SP to processor/multifactor so the response carries the correct `AuthnContextClassRef`.

---

## 8. SLO robustness

- **Proposal:**  
  - Ensure the session/user logged out matches the NameID in the SLO request when multiple sessions exist.  
  - If SOAP SLO is added, implement back-channel logout and document flow.

---

## 9. Rate limiting

- **Proposal:** Optional rate limiting (by IP or SP entity_id) on SSO entry and login process views to mitigate abuse.

---

## 10. Priority summary

| Priority   | Extension              | Effort | Impact  |
|-----------|-------------------------|--------|--------|
| High      | Transient NameID        | Low    | High   |
| High      | Audit logging (SSO/SLO) | Low    | High   |
| Medium    | Request expiration       | Low    | Medium |
| Medium    | SP metadata refresh job | Low    | Medium |
| Medium    | Health endpoint         | Low    | Medium |
| Lower     | SOAP SLO                | Medium | If needed |
| Lower     | More NameID formats     | Medium | If needed |
| Lower     | Rate limiting           | Low    | Optional |

---

## Revision history

| Rev | Date       | Changes                          |
|-----|------------|-----------------------------------|
| 1   | 2026-02-24 | Initial proposal (add/update/extend plan). |
