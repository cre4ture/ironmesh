# Bootstrap Claim QR Strategy

Status: Proposed replacement for full-bootstrap QR transfer

Related:

- `docs/zero-touch-cluster-setup-strategy.md`
- `docs/nat-traversal-rendezvous-strategy.md`
- `docs/security-architecture.md`

## 1. Problem

The current server-admin QR path encodes the full client bootstrap JSON directly into one QR code.

That bootstrap is large because it includes:

- `cluster_id`
- `rendezvous_urls`
- `direct_endpoints`
- relay policy
- trust roots
- pairing/enrollment secret material
- optional device metadata

In practice this makes the QR dense and hard to scan reliably from a phone screen.

## 2. Goal

Keep the operator UX simple while reducing QR payload size dramatically.

Requirements:

- scanning must be reliable from another device screen,
- the flow must work when only the rendezvous service is directly reachable,
- the fetch endpoint must still be secure even when it is not trusted by public PKI,
- pairing/enrollment secrets must remain short-lived and one-time-use,
- the Android client should still end up with the same full bootstrap/enrollment result it gets today.

## 3. Decision

Do not put the full bootstrap bundle in the QR.

Instead, the QR should carry a small bootstrap-claim payload that contains:

- a stable primary rendezvous/service URL,
- an optional ordered list of fallback rendezvous/service URLs,
- minimal trust bootstrap for that rendezvous endpoint,
- a short-lived one-time claim token,
- a small amount of display/verification metadata such as `cluster_id` and expiry.

The client scans this small claim, establishes a pinned TLS connection to the rendezvous-facing claim endpoint, redeems the claim, and receives the full client bootstrap bundle over the network.

## 4. Why rendezvous must be the redeem endpoint

This strategy should assume that an arbitrary server node may not be directly reachable from the client at bootstrap time.

If only the rendezvous service is directly reachable, the redeem flow is still possible as long as the claim is redeemed through the rendezvous service or a stable public endpoint that fronts it.

Recommended rule:

- the public redeem endpoint should live on the rendezvous service,
- server nodes may issue claims and store them locally,
- the claim payload must include `target_node_id` so rendezvous can route redemption to the right node,
- the mobile client should not need direct reachability to the issuing node just to fetch the bootstrap.

This keeps the bootstrap retrieval path aligned with the NAT/relay model rather than fighting it.

## 5. Trust model when the redeem endpoint is not public-PKI

The redeem endpoint must not assume a browser-style public-PKI trust store.

That means the QR claim needs to carry enough trust bootstrap for the mobile app to authenticate the rendezvous endpoint before redeeming the claim.

Acceptable trust-bootstrap shapes:

1. `rendezvous_ca_der_b64u`

- recommended default,
- carries the same certificate trust information as PEM but without PEM armor overhead,
- removes:
  - `-----BEGIN CERTIFICATE-----`
  - `-----END CERTIFICATE-----`
  - line wrapping/newlines,
- the client base64url-decodes the value into DER and pins or validates HTTPS against that CA.

2. `rendezvous_ca_pem`

- simplest conceptually,
- useful as an interim/debug format,
- larger because the QR has to carry PEM headers, footers, and line breaks.

3. `rendezvous_ca_spki_sha256` or `rendezvous_leaf_spki_sha256`

- smallest QR payload,
- requires explicit certificate/public-key pinning support in the client,
- operationally stricter because cert/key rotation must keep the pin valid or reissue fresh claims.

Recommended rollout:

- prefer `rendezvous_ca_der_b64u` as the first real implementation,
- keep PEM only as an implementation/debug fallback if needed,
- move to SPKI pinning later only if the claim QR still needs to be smaller.

## 6. Proposed claim payload

Example QR payload:

```json
{
  "version": 1,
  "kind": "client_bootstrap_claim",
  "cluster_id": "cluster-alpha",
  "target_node_id": "7a4f2a38-8e32-4b37-919d-9bb07a5a0a27",
  "rendezvous_url": "https://rendezvous.example:9443",
  "rendezvous_urls": [
    "https://rendezvous.example:9443",
    "https://rendezvous-backup.example:9443"
  ],
  "trust": {
    "mode": "rendezvous_ca_der_b64u",
    "ca_der_b64u": "MIIC..."
  },
  "claim_token": "base64url-or-hex-high-entropy-token",
  "expires_at_unix": 1900003600
}
```

Notes:

- this payload should stay small and stable,
- it should not contain full direct endpoint lists or the final bootstrap bundle,
- it should not contain anything that requires direct access to a specific server node,
- `rendezvous_url` remains the primary redeem endpoint while `rendezvous_urls` can carry backup public rendezvous endpoints in priority order,
- trust material should avoid PEM armor in the QR when possible,
- the claim token is the bearer secret and must be treated accordingly.

## 7. Redemption flow

### 7.1 Admin/UI side

1. Operator clicks `Issue bootstrap claim`.
2. Server node creates the full client bootstrap bundle as it does today.
3. Server node creates a short-lived one-time claim record.
4. Server node stores that claim locally on the issuing node.
5. Server node returns the small claim payload to the admin UI, including the primary rendezvous URL and any additional currently healthy/registered rendezvous URLs.
6. Admin UI renders the QR from that small claim payload.

### 7.2 Client side

1. Android app scans the QR.
2. App parses the small claim payload.
3. App establishes HTTPS to the ordered rendezvous URLs from the claim, using the trust bootstrap from the QR instead of the public system trust store.
4. App redeems the claim with an explicit request such as:
   - `POST /bootstrap-claims/redeem`
5. Rendezvous validates that the target node is currently present and then relays the redeem request over the authenticated relay tunnel to `target_node_id`.
6. The target node validates:
   - token exists,
   - token not expired,
   - token not consumed,
   - target-node binding matches the local node.
7. The target node returns the full client bootstrap bundle and issued client credentials through that same tunnel.
8. Rendezvous forwards the response to the app.
9. App continues normal enrollment/bootstrap handling from that point onward.

## 8. Security requirements

The claim token must be treated like a short-lived bearer secret.

Required safeguards:

- token must be high entropy,
- token must be one-time-use,
- token must expire quickly,
- redemption must happen over pinned HTTPS,
- the redeem operation must not be consumed by a casual `GET` page load,
- claim tokens must not be logged in plaintext,
- responses should use `Cache-Control: no-store`,
- redemption attempts should be rate-limited.

Operational safeguards for node-owned claims:

- rendezvous should reject redeem attempts early when `target_node_id` is not currently present,
- invalid redeem attempts will reach the target node, so rate limits should apply at rendezvous and the node,
- node-side redeem handlers should check the claim record before doing expensive enrollment work.

Important implementation rule:

- scanning a URL must not immediately consume the claim through browser/scanner prefetch behavior.

Preferred pattern:

- the QR opens the app or carries structured JSON,
- the app performs the explicit redeem `POST`,
- only that explicit redeem call consumes the claim.

## 9. Relationship to rendezvous and relay

This claim strategy is compatible with the broader NAT/relay architecture:

- the rendezvous service is already the public connectivity anchor,
- redeeming via rendezvous avoids assuming direct access to a particular node while still letting the issuing node own claim state,
- the full bootstrap can still contain direct endpoint hints for later path optimization,
- relay/direct path selection remains a later transport concern, not part of QR delivery itself.

The QR transport problem and the client transport problem stay separated:

- QR gets the client to a trusted claim redeem path,
- the redeemed full bootstrap tells the client how to operate afterward.

## 10. Fallback UX

For the first implementation, the recommended UX should stay narrow:

- primary: scan QR claim,
- operator fallback: download/import bootstrap file.

Not in scope for the first implementation:

- manual short claim-code entry.

Reason:

- it adds another user-facing flow and another redeem surface,
- it is not required if QR scanning is assumed to be reliably available on current devices,
- the design effort should stay focused on making the QR payload itself small and robust.

## 11. Explicit non-goal

This strategy does not depend on direct reachability to a server node during the initial scan.

If only the rendezvous service is reachable, the design should still succeed.

That is a core requirement, not an edge case.
