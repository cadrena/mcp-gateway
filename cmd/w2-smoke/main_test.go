package main

import (
	"context"
	"testing"

	"github.com/cadrena/dsl"
	pe "github.com/cadrena/policy-engine"
)

func TestSmokeRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("CADRENA_RUN_STRIPE_SMOKE", "")
	if run() == nil {
		t.Fatal("smoke ran without opt-in")
	}
}

func TestSmokeSeedAndPolicy(t *testing.T) {
	ctx := context.Background()
	engine, err := seed(ctx, "cus_fixture")
	if err != nil {
		t.Fatal(err)
	}
	caller, err := pe.NewCaller("gateway", nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := pe.NewSelector("active", "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := pe.NewContextualData(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		amount   int64
		decision pe.Decision
	}{{10000, pe.DecisionAllow}, {10001, pe.DecisionRequireApproval}, {50000, pe.DecisionRequireApproval}, {50001, pe.DecisionDeny}} {
		request, err := pe.NewCheckRequest(pe.CheckRequestInput{Namespace: "demo", Selector: selector, Subject: dsl.EntityRef{Type: "user", ID: "demo-user"}, Resource: dsl.EntityRef{Type: "customer", ID: "cus_fixture"}, Action: "refund", Arguments: map[string]pe.Value{"amount_minor": pe.NewIntegerValue(tc.amount)}, ContextualData: data})
		if err != nil {
			t.Fatal(err)
		}
		response, err := engine.Check(ctx, caller, request)
		if err != nil {
			t.Fatal(err)
		}
		if response.Result().Decision() != tc.decision {
			t.Fatal("incorrect smoke policy")
		}
	}
}
