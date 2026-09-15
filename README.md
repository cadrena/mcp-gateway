# MCP Gateway

## Status

W2 implementation with a durable journal and Stripe test adapter. Go 1.25.13.

The embedded Gateway validates each call against a pinned tool schema and the public Policy Engine.
Only an ALLOW decision reaches the configured upstream tool.
DENY, REQUIRE_APPROVAL, invalid input, and authorization errors prevent dispatch.

The local test suite covers durable dispatch and the Stripe adapter with a mock provider.
The demo release gate uses the stateful local refund simulator.
Live Stripe validation is a separate, optional integration check.
The public Gateway release still requires the simulator acceptance and clean tagged consumption checks.
Approval continuation still requires the later private workflow.

## Roadmap

A demo Gateway release follows the local simulator acceptance and clean public consumption checks.
Simulation does not verify Stripe compatibility or payment processing.

## API

- `New(Config)` requires a journal and copies tool mappings and schema bytes into an immutable Gateway.
- `NewIdentity(actor, agent, task)` constructs a trusted host identity.
- `Invoke(ctx, identity, call)` requires a stable host invocation ID and commits the journal before dispatch.
- `BatchCheck(ctx, identity, calls)` checks up to 16 calls under one Engine snapshot. It never dispatches.
- `NewHTTPHandler(gateway, HTTPConfig)` exposes configured tools through stateless Streamable HTTP.
- `transport.New(Config)` creates a bounded upstream client with an explicit network allowlist.
- `journal/sqlite.Open(path)` opens a journal with exclusive process ownership.

Identity construction does not authenticate a user. The host must verify credentials and current agent access.
HTTP authentication runs on every request. Tool arguments cannot select the caller, namespace, agent, or policy slot.
The host must serve the handler with TLS and appropriate HTTP timeouts.
Every HTTP tools/call request requires one `Idempotency-Key` header with 16–128 permitted ASCII characters.
Use the same value when retrying the same invocation. The model must not supply this header.
The Gateway derives the upstream key from the namespace, caller, and invocation ID.
It sends that key through trusted MCP metadata, not tool arguments.

## Durable dispatch

The journal commits `authorized`, then commits `dispatch_started`, before the tool call.
The final state is `completed` or `outcome_unknown`.
Completed outcomes distinguish success, failure, and pending results.
The journal stores hashes and decision references. It stores no arguments, credentials, or provider response body.

A retained invocation cannot dispatch twice. Matching repeats return a replay error.
Changed arguments or identities under the same retained ID return a conflict.
DENY and REQUIRE_APPROVAL do not create execution records. Their private workflow remains separate.
The journal has no deletion or retention operation in this milestone.

On restart, the store quarantines `authorized` rows and marks `dispatch_started` rows unknown.
It never recreates execution rights from those rows. The old lease expires with the store instance.
Another process cannot open the journal while its owner holds the lock.
The SQLite adapter supports Linux and macOS. Its directory must be private, owned by the current user, and mode 0700.
See [journal details](journal/README.md).

Preserve the journal between runs. Do not use a new ID to retry an unknown outcome.
Backups require the later restore procedure; this milestone does not prove safe recovery from an old backup.
These controls prevent automatic replay. They do not promise exactly-once execution in an external service.

## Local refund demo

The local example uses a persistent simulated payment ledger. It needs no provider account or key.
It exercises both MCP endpoints, the embedded Engine, and the durable Gateway journal.
No real payment provider receives a request.

```sh
go run ./cmd/w2-local-demo --state-dir /absolute/private/demo-state
```

Keep the state directory between runs. A matching rerun must not deduct the balance again.
The command checks allow, deny, approval requirements, access boundaries, and replay behavior.
Approval cases stop without a refund; private approval continuation remains separate work.
The output identifies every result as simulated.

See [the simulator example](examples/refund-simulator/README.md) for its limits.

## Stripe test runner

The [refund adapter](examples/refund-upstream/README.md) accepts test keys and existing Charge objects only.
It verifies the customer, currency, test mode, capture status, and refundable balance before the refund POST.
It preserves provider pending and failed statuses. It never follows redirects or retries a refund POST.

The complete runner is `go run ./cmd/w2-smoke`.
It starts both MCP endpoints on loopback and invokes the real Engine and journal.
Set these environment variables through your local secret configuration:

- `CADRENA_RUN_STRIPE_SMOKE=1` explicitly enables the test refund.
- `STRIPE_TEST_API_KEY` contains a Stripe test secret or restricted key.
- `STRIPE_TEST_CUSTOMER` identifies the customer attached to the test Charge.
- `STRIPE_TEST_CHARGE` identifies an existing refundable USD Charge.
- `CADRENA_JOURNAL_PATH` contains an absolute path in a private directory.
- `CADRENA_INVOCATION_ID` contains a stable 16–128 character request ID.
- `STRIPE_TEST_AMOUNT_MINOR` optionally sets the amount. The default is 100 cents.

The runner creates no customers or payments. Amounts above 10000 cents require approval and do not refund.
The runner has no approval continuation. Keep credentials and journal files outside source control.

## Supported profile

The protocol version is `2026-07-28`. The transport uses JSON responses and disables automatic tool retries.
The server checks the Host and Origin against explicit lists. It rejects duplicate JSON keys and oversized requests.

Schemas must declare an object, flat scalar properties, and `additionalProperties: false`.
Supported types are string, integer, boolean, and null.
Supported constraints are required properties, integer bounds, string lengths, and enums.
Unknown schema keywords fail closed. This includes unsupported annotations and nested structures.
Integer arguments use exact signed 64-bit values. Fractional and exponent forms are rejected.
The resource identifier must come from a nonempty string argument.

The Gateway checks the remote schema before each evaluation.
New remote tools do not enter the configured catalog automatically.
The caller digest includes every normalized argument, identity field, connection version, schema, and mapping.
Configuration changes require a new Gateway instance. Hosts must retire old instances and pending work.
Remote schema checks detect drift; they cannot make an untrusted remote server honor its declared schema.

Use `transport.Client` for remote servers. Custom upstream ports are trusted host code.
The transport checks resolved addresses at each dial and connects to the checked address.
It disables environment proxies and redirects. Private networks require explicit subnets; metadata targets remain blocked.
Plain HTTP requires an explicit loopback test setting.

## Verification

Dependencies use published versions without local replacements.
Run these commands from this repository:

```sh
go test -race -count=1 ./...
go vet ./...
go build ./...
go mod verify
```

Ordinary tests use fixtures. They do not contact Stripe, Slack, or a model server.
The opt-in smoke runner contacts Stripe test mode only.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Trusted approval continuation

`Invoke` and the HTTP MCP endpoint accept no approval evidence. Embedded hosts
can use `Resume(ctx, identity, call, approval, boundary)` for an existing request.
`Approval` contains opaque evidence and the original Engine binding digest.
Keep both outside client arguments, logs, and public responses.

`Result.InvocationKey` and `Result.RequestDigest` expose canonical metadata to
trusted hosts after preparation. Store these with the original decision and
request. They identify the invocation; they do not grant execution authority.
Do not reconstruct the Gateway envelope in private code.

`Resume` performs these steps:

1. Validate the request and current catalog outside a transaction.
2. Reject an existing journal record or a changed request under the same ID.
3. Require a fresh `REQUIRE_APPROVAL` decision with the saved binding digest.
4. Run optional read validation outside the transaction.
5. Call the host's `AuthorizationBoundary.WithinAuthorization` method.
6. Recheck with evidence inside its transaction and require `ALLOW` with `UsedApproval`.
7. Verify the returned lease binding, then call the configured journal's `Start`.
8. Dispatch after that commit, then persist the known or uncertain outcome.

The boundary must call its callback exactly once, synchronously. It supplies a
transaction context to the Engine verifier. The verifier must consume the exact
saved grant within that transaction. The boundary commits consumption, the
returned journal record, invocation state, durable audit, and outbox together.
Only a successful commit permits the journal issuer to create a lease. An
uncertain commit returns an error and prevents dispatch.

The host must check the invocation, tenant, current actor and agent access,
connection version, approver authority, self-approval rule, and expiry. Recheck
expiry and current authority before the dispatch CAS. The Engine, verifier,
caller authorizer, and decision sink used inside the callback must make no
network calls. The callback preserves transaction values and links cancellation
to the original request. Resume limits its context to thirty seconds.

A new ALLOW, DENY, revision, or data generation cannot substitute for the saved
approval. A matching base approval permits read validation, not mutation.
`Lease.Matches` checks only key and digest. `Store.Start` still authenticates the
configured issuer and commits its state transition.

Duplicate, skipped, unfinished, and late callback attempts cannot produce a new
dispatch through Resume. Hosts must honor cancellation and cannot retain their
transaction handles. Recovery must quarantine old authorized rows and preserve
uncertain dispatched outcomes. This API does not implement Slack, private SQL,
worker recovery, or grant retention.
