# Stripe test refund adapter

This example exposes `stripe.refund_payment` through authenticated MCP.
It supports existing test Charges with `ch_` identifiers and USD amounts.
It does not support PaymentIntent identifiers.

The adapter uses only `https://api.stripe.com`.
It accepts `sk_test_` and `rk_test_` credentials.
It rejects live credentials and live Charge objects.
Production code offers no endpoint override.
Tests use an internal mock endpoint.

## Request contract

The tool accepts exactly three fields:

| Field | Meaning |
| --- | --- |
| `customer` | Expected Stripe customer identifier with a `cus_` prefix |
| `payment` | Existing Stripe Charge identifier with a `ch_` prefix |
| `amount_minor` | Positive integer amount in USD cents |

The parser rejects duplicate fields, extra fields, fractions, numeric strings, and overflow.
The schema uses the Gateway's supported scalar constraints.
The adapter checks identifier prefixes and ASCII characters separately.

The authenticated Gateway supplies `_meta["cadrena/idempotency-key"]`.
This value contains exactly 64 lowercase hexadecimal characters.
The adapter copies it to the Stripe `Idempotency-Key` header.
The model must not supply this value as a tool argument.

The Gateway must authorize the user for the customer.
The adapter checks the Charge's customer, test mode, currency, capture state, and remaining amount.
The adapter repeats these checks immediately before the refund request.
The payment read does not replace the Gateway's authorization decision.

## Result contract

The adapter returns a bounded result with `refund_id`, `status`, `amount_minor`, and `currency`.
It preserves `succeeded`, `failed`, and `pending` statuses.
A pending refund does not mean that the customer received the refund.

A timeout, server error, malformed response, or unsupported result produces an unknown outcome.
The MCP handler returns an RPC error for this outcome.
The Gateway must record `outcome_unknown` and stop automatic retries.
Known validation failures return an error result without a Stripe refund request.

Each HTTP request has a timeout and a response limit of 1 MiB.
The client disables proxies, redirects, persistent connections, and automatic retries.
The adapter has no durable journal.
The Gateway must commit its dispatch state before the remote tool call.

## Serve the MCP endpoint

Set these environment variables in the server environment:

| Variable | Purpose |
| --- | --- |
| `STRIPE_TEST_API_KEY` | Test secret key or restricted test key |
| `CADRENA_GATEWAY_BEARER` | Separate Gateway credential, with at least 16 printable characters |
| `CADRENA_REFUND_HOSTS` | Exact permitted Host values, separated by commas |
| `CADRENA_REFUND_ORIGINS` | Optional exact Origin values, separated by commas |
| `CADRENA_REFUND_LISTEN` | Listen address; the default is `127.0.0.1:8099` |

Keep the Gateway credential away from agents and browsers.
Use the endpoint `/mcp`.
Configure TLS at the deployment boundary for remote access.
An empty origin list accepts requests without an Origin header only.

Run this command from the repository root:

```sh
rtk proxy go run ./examples/refund-upstream/cmd/refund-upstream -mode serve
```

## Check an existing test payment

Set `STRIPE_TEST_CUSTOMER`, `STRIPE_TEST_CHARGE`, and `STRIPE_TEST_AMOUNT_MINOR`.
Supply an existing test Charge that belongs to the specified customer.
Do not use a PaymentIntent identifier.

```sh
rtk proxy go run ./examples/refund-upstream/cmd/refund-upstream -mode validate
```

This command reads the Charge.
It does not create payments, customers, or refunds.

Use the repository's `cmd/w2-smoke` command for an explicit refund through the Gateway and journal.
That command requires its own opt-in flag and test fixture variables.
Preserve its invocation identifier and journal when an outcome is uncertain.

## Verification

```sh
rtk proxy go test -race ./examples/refund-upstream/... -count=1
rtk proxy go vet ./examples/refund-upstream/...
```

The tests use local HTTP fixtures, an actual Engine, and a SQLite journal.
They check ownership, balance, statuses, metadata, authentication, error limits, replay, and conflict behavior.
The vertical test includes the real MCP client and adapter handler.
It verifies one refund request for success, pending, and ambiguous server outcomes.

These tests do not contact Stripe.
They do not verify a real Stripe account, credential permission, or payment fixture.
Live test evidence requires an explicit smoke run with supplied credentials.

## API references

- [Retrieve a Charge](https://docs.stripe.com/api/charges/retrieve) defines the payment read.
- [Charge fields](https://docs.stripe.com/api/charges/object) define customer, mode, and amount checks.
- [Create a refund](https://docs.stripe.com/api/refunds/create) defines the Charge and minor-unit amount parameters.
- [Refund fields](https://docs.stripe.com/api/refunds/object) define the returned status.
- [Idempotent requests](https://docs.stripe.com/api/idempotent_requests) describe provider key behavior.

Stripe's key retention does not replace the Gateway journal.
