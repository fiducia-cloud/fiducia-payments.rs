// Bounded executable model of the pure provider-webhook verification boundary.
//
// Production mapping:
//   configuration_valid -> non-empty Stripe secret; supported PayPal algorithm
//                          and non-empty configured webhook id
//   envelope_valid      -> parseable Stripe signature header; decodable PayPal
//                          signature and certificate
//   provenance_valid    -> Stripe replay window; PayPal HTTPS paypal.com cert URL
//   signature_valid     -> HMAC/RSA verification over the exact raw body
//   event_valid         -> VerifiedEvent::from_body finds string identity + type
//
// PayPal transmission_time is cryptographically bound but is not age-checked by
// the current public verifier. That distinct freshness gap is tracked by issue
// #9 and is deliberately not claimed by this current-semantics model.
module provider_verification {
  type State = {
    phase: int,
    provider: int,
    configuration_valid: bool,
    envelope_valid: bool,
    provenance_valid: bool,
    signature_valid: bool,
    event_valid: bool,
    outputs: int,
    consumes: int,
  }

  pure val PHASE_RECEIVED = 0
  pure val PHASE_VERIFIED = 1
  pure val PHASE_REJECTED = 2
  pure val PHASE_CONSUMED = 3
  pure val PHASE_CLOSED = 4

  pure val PROVIDER_STRIPE = 1
  pure val PROVIDER_PAYPAL = 2

  pure val GATE_CONFIGURATION = 1
  pure val GATE_ENVELOPE = 2
  pure val GATE_PROVENANCE = 3
  pure val GATE_SIGNATURE = 4
  pure val GATE_EVENT = 5

  pure val PROVIDERS: Set[int] = Set(PROVIDER_STRIPE, PROVIDER_PAYPAL)
  pure val GATES: Set[int] = Set(
    GATE_CONFIGURATION,
    GATE_ENVELOPE,
    GATE_PROVENANCE,
    GATE_SIGNATURE,
    GATE_EVENT
  )

  var s: State

  pure def verification_inputs_valid(state: State): bool = and {
    PROVIDERS.contains(state.provider),
    state.configuration_valid,
    state.envelope_valid,
    state.provenance_valid,
    state.signature_valid,
    state.event_valid,
  }

  action init_with_provider(provider: int): bool = all {
    PROVIDERS.contains(provider),
    s' = {
      phase: PHASE_RECEIVED,
      provider: provider,
      configuration_valid: true,
      envelope_valid: true,
      provenance_valid: true,
      signature_valid: true,
      event_valid: true,
      outputs: 0,
      consumes: 0,
    },
  }

  action init: bool = {
    nondet provider = PROVIDERS.oneOf()
    init_with_provider(provider)
  }

  action invalidate(gate: int): bool = all {
    s.phase == PHASE_RECEIVED,
    GATES.contains(gate),
    s' = {
      ...s,
      configuration_valid:
        if (gate == GATE_CONFIGURATION) false else s.configuration_valid,
      envelope_valid:
        if (gate == GATE_ENVELOPE) false else s.envelope_valid,
      provenance_valid:
        if (gate == GATE_PROVENANCE) false else s.provenance_valid,
      signature_valid:
        if (gate == GATE_SIGNATURE) false else s.signature_valid,
      event_valid:
        if (gate == GATE_EVENT) false else s.event_valid,
    },
  }

  action verify: bool = all {
    s.phase == PHASE_RECEIVED,
    verification_inputs_valid(s),
    s' = {
      ...s,
      phase: PHASE_VERIFIED,
      outputs: 1,
    },
  }

  action reject: bool = all {
    s.phase == PHASE_RECEIVED,
    not(verification_inputs_valid(s)),
    s' = {
      ...s,
      phase: PHASE_REJECTED,
    },
  }

  action consume: bool = all {
    s.phase == PHASE_VERIFIED,
    s.outputs == 1,
    s.consumes == 0,
    s' = {
      ...s,
      phase: PHASE_CONSUMED,
      consumes: 1,
    },
  }

  // Provider retries after a completed decision are observational no-ops at
  // this pure verifier boundary. Durable event-id/payload-digest idempotency is
  // enforced in fiducia-customer.rs.
  action retry: bool = all {
    Set(PHASE_VERIFIED, PHASE_REJECTED, PHASE_CONSUMED).contains(s.phase),
    s' = s,
  }

  action close: bool = all {
    s.phase != PHASE_CLOSED,
    s' = {
      ...s,
      phase: PHASE_CLOSED,
    },
  }

  action idle: bool = s' = s

  action step: bool = {
    nondet gate = GATES.oneOf()
    any {
      invalidate(gate),
      verify,
      reject,
      consume,
      retry,
      close,
      idle,
    }
  }

  val authentication_safety = and {
    Set(
      PHASE_RECEIVED,
      PHASE_VERIFIED,
      PHASE_REJECTED,
      PHASE_CONSUMED,
      PHASE_CLOSED
    ).contains(s.phase),
    PROVIDERS.contains(s.provider),
    s.outputs >= 0,
    s.outputs <= 1,
    s.consumes >= 0,
    s.consumes <= 1,
    s.consumes <= s.outputs,
    (s.outputs == 1).implies(and {
      verification_inputs_valid(s),
      Set(PHASE_VERIFIED, PHASE_CONSUMED, PHASE_CLOSED).contains(s.phase),
    }),
    (s.consumes == 1).implies(
      Set(PHASE_CONSUMED, PHASE_CLOSED).contains(s.phase)
    ),
    (s.phase == PHASE_RECEIVED).implies(and {
      s.outputs == 0,
      s.consumes == 0,
    }),
    (s.phase == PHASE_REJECTED).implies(and {
      s.outputs == 0,
      s.consumes == 0,
    }),
  }

  val stripe_verified = and {
    s.provider == PROVIDER_STRIPE,
    s.outputs == 1,
  }
  val paypal_verified = and {
    s.provider == PROVIDER_PAYPAL,
    s.outputs == 1,
  }
  val rejection_reached = s.phase == PHASE_REJECTED
  val consumption_reached = s.consumes == 1
}
