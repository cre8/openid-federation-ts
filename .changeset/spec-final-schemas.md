---
"@openid-federation/core": minor
---

Read entity configurations of OpenID Federation 1.0 final.

- Trust marks accept `trust_mark_type`. The draft `id` is still read and mapped to `trust_mark_type`. The `trust_mark_type` of a `trust_marks` entry must be the one of its trust mark JWT.
- Decoded JWTs, such as `trust_marks[].trust_mark`, keep the compact JWT in `jwt`, so a trust mark can be verified.
- Metadata keeps parameters and entity types the schemas do not define. Before, for example, `token_endpoint` of `oauth_authorization_server` and every unknown entity type were dropped, also from `resolvedLeafMetadata`.
- `client_registration_types_supported` of `openid_credential_issuer` and `client_registration_types` of `openid_credential_verifier` are optional.
- `Date` values of claims such as `iat` and `exp` are signed as NumericDate (seconds since the epoch) instead of ISO strings (#23).
