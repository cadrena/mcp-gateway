# Local refund simulator

This example demonstrates authorization against a persistent local payment ledger.
It does not implement Stripe or move money.

The tool is `demo.refund_payment`. Its arguments identify a customer, a payment, and an integer amount in minor units.
The fixture uses USD. Seed operations preserve existing balances rather than resetting completed refunds.
A durable idempotency key identifies each simulated refund.
Matching repeats preserve the original result; changed requests conflict.

## Run the acceptance example

From the Gateway repository, run:

```sh
go run ./cmd/w2-local-demo --state-dir /absolute/private/demo-state
```

Use a private local directory. Keep its ledger and journal for matching reruns.
The example needs no Stripe key, Slack workspace, or model endpoint.
It exercises actual MCP transport, Engine decisions, and journal writes against simulated payment state.

The acceptance command checks the 100 USD and 500 USD boundaries, user access, and replay protection.
Approval requirements remain pending; the example does not fabricate a human approval.

## Evidence boundary

Stripe's official stripe-mock is stateless and does not model changing balances.
Its documentation recommends custom mocks for more advanced regression testing.
Source: https://github.com/stripe/stripe-mock#features-and-limitations

This focused example keeps local state to demonstrate mutations and repeated requests.
It does not prove Stripe API compatibility, real settlement, provider idempotency retention, or provider failure semantics.
The existing live Stripe test adapter remains separate and unchanged.
