Key service hardening
=====================

The SOPS key service (`sops keyservice`) exposes an RPC that encrypts and
decrypts SOPS data keys with server-side master keys. By default it is a
*local* facility: it listens on the loopback interface, has no caller
authentication, and trusts anyone who can reach the port.

This document describes the optional boundary controls. **None of them are
required for in-process use**: `keyservice.NewLocalClient()` and every command
that does not pass `--keyservice` behave exactly as before.

Default-deny boundary
---------------------

The key service refuses to start when it would expose an unauthenticated
listener to the network:

* A plaintext listener, or a TLS listener without `--tls-client-ca`, is only
  allowed on `127.0.0.1`, `::1`, `localhost` or a unix socket.
* `--allow-anonymous` admits unauthenticated callers explicitly, and is only
  allowed on a loopback or unix address. Anonymous admission is logged and
  counted.
* A non-local address requires `--tls-client-ca`, so every connection presents
  a verified client certificate.

Configuration errors (missing or expired certificate, malformed address,
broken policy) fail at startup, before the socket is opened.

Server
------

```console
sops keyservice \
  --network tcp --address 0.0.0.0:5000 \
  --tls-cert /etc/sops/server.pem \
  --tls-key /etc/sops/server.key \
  --tls-client-ca /etc/sops/client-ca.pem \
  --policy /etc/sops/keyservice-policy.yaml \
  --request-timeout 15s --queue-timeout 3s \
  --max-concurrent 8 --max-queued 64 \
  --rate-limit 20 --rate-burst 5 \
  --metrics-period 1m
```

| Flag | Meaning |
| --- | --- |
| `--tls-cert`, `--tls-key` | Encrypt the transport. |
| `--tls-client-ca` | Require and verify a client certificate. Enables caller identity and scope rules. |
| `--tls-min-version` | `1.2` (default) or `1.3`. |
| `--allow-anonymous` | Explicitly admit unauthenticated callers (local only). |
| `--policy` | YAML/JSON scope policy (see below). |
| `--request-timeout` | Per-backend-operation deadline (default `30s`). When it fires, the RPC returns `DeadlineExceeded` and the backend call is released. |
| `--queue-timeout` | Maximum wait for a worker (default `5s`). |
| `--max-concurrent`, `--max-queued` | Worker slots and bounded queue. A full queue is rejected immediately. |
| `--rate-limit`, `--rate-burst` | Token bucket. `0` disables. Rejections use `ResourceExhausted`. |
| `--metrics-period` | How often concurrency, queue depth and rejection counters are logged. |

Scope policy
------------

```yaml
rules:
  - name: decrypt-for-ops
    callers:
      - "ops-*"                       # client certificate common name
      - "DNS=ops.example.com"         # or a DNS SAN
    keys:
      - "age:age1ops*"                # age recipient pattern
      - "pgp:*"                       # any PGP key
      - "kms:arn:aws:kms:eu-west-1:123456789012:key/*"
    operations: [decrypt]             # default: both encrypt and decrypt

  - name: rotate-for-build
    callers: ["CN=build-client"]
    keys: ["kms:arn:aws:kms:eu-west-1:123456789012:key/*"]
```

* Caller patterns match the certificate CN, a DNS SAN or a URI SAN. `*` and
  `?` are wildcards. `anonymous` and `local` are accepted identifiers.
* Key patterns are `<type>` or `<type>:<identifier glob>`, where type is one of
  `kms`, `pgp`, `gcp_kms`, `azure_kv`, `hc_vault`, `age`, `hckms`, or `*`.
* The first matching rule decides the outcome. A caller that matches no rule is
  denied. The policy also governs in-process calls, which are identified as
  `local`.
* A key outside the caller's scope returns `PermissionDenied` with the message
  "requested key is outside of the caller's permitted scope". The error, the
  audit log and the metrics never contain the key identifier or key material.

The decision is made **before** the backend call and before the interactive
prompt. No ciphertext is sent to a backend that the caller may not use.

Client
------

Remote clients opt into TLS explicitly. Without TLS flags the existing
plaintext connection is kept, so old clients still reach unhardened instances:

```console
sops decrypt --keyservice tcp://keys.example.com:5000 \
  --keyservice-tls-ca /etc/sops/ca.pem \
  --keyservice-tls-cert /etc/sops/client.pem \
  --keyservice-tls-key /etc/sops/client.key \
  --keyservice-tls-server-name keys.example.com \
  --keyservice-tls-expected-server-identity keys.example.com \
  --keyservice-timeout 10s \
  secrets.enc.yaml
```

`--keyservice-tls-expected-server-identity` pins the server certificate to a
CN, DNS SAN or URI SAN. A mismatch aborts the connection with
`ErrServerIdentityMismatch`; it never falls back to an unverified connection.
An expired peer certificate is reported as `ErrPeerCertificateExpired`.

Audit and observability
-----------------------

Every request emits one `keyservice.request` record with `caller`,
`operation` (`encrypt`, `decrypt` or `handshake`), `key_type`, `outcome`
(`allowed`, `denied`, `error`), a sanitized `reason`, `peer` and `duration`.
Refused TLS handshakes are recorded too. Key identifiers, ciphertext and
plaintext are never logged.

Periodic `keyservice.metrics` records expose `requests`, `allowed`, `denied`,
`errors`, `rate_limited`, `queue_full`, `queue_timeouts`, `backend_timeouts`,
`anonymous`, `in_flight`, `queued` and `workers`. The raw counters are also
available in-process through `keyservice.Metrics.Snapshot()`.

Error classification
--------------------

| Situation | gRPC code | Sentinel (in-process) |
| --- | --- | --- |
| No verified caller | `Unauthenticated` | `ErrAuthenticationRequired` |
| Caller matches no rule | `PermissionDenied` | `ErrCallerNotAuthorized` |
| Key outside scope | `PermissionDenied` | `ErrKeyOutOfScope` |
| Rate limit / queue full / queue timeout | `ResourceExhausted` | `ErrRateLimited`, `ErrQueueFull`, `ErrQueueTimeout` |
| Backend timeout | `DeadlineExceeded` | `ErrBackendTimeout` |

`keyservice.IsAuthorizationError` and `keyservice.IsTimeout` classify errors
without inspecting messages. Peer rejections and backend timeouts are therefore
distinguishable.
