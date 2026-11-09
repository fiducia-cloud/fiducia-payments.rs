// Six-gate bounded model for the NEW paypal::verify_at API, not the legacy
// paypal::verify API. Real RSA/X.509 and timestamp parsing refine these gates
// in tests/paypal_freshness.rs (all 64 valid/invalid combinations).
//
// Configuration: nonempty configured webhook id + accepted algorithm
// Envelope: decodable signature + certificate
// Provenance: authenticated cert URL under HTTPS paypal.com
// Signature: exact bytes, signed transmission id/time and webhook id
// Event: validated event identity + event type
// Freshness: signed RFC3339 instant within the injected inclusive tolerance

module paypal_freshness {
  type State = {
    phase: int,
    configuration_valid: bool,
    envelope_valid: bool,
    provenance_valid: bool,
    signature_valid: bool,
    event_valid: bool,
    freshness_valid: bool,
    outputs: int,
    consumes: int,
  }

  pure val PHASE_RECEIVED = 0
  pure val PHASE_VERIFIED = 1
  pure val PHASE_REJECTED = 2
  pure val PHASE_CONSUMED = 3
  pure val PHASE_CLOSED = 4

  pure val GATE_CONFIGURATION = 1
  pure val GATE_ENVELOPE = 2
  pure val GATE_PROVENANCE = 3
  pure val GATE_SIGNATURE = 4
  pure val GATE_EVENT = 5
  pure val GATE_FRESHNESS = 6
  pure val GATES: Set[int] = Set(1, 2, 3, 4, 5, 6)

  var s: State

  pure def valid(state: State): bool = and {
    state.configuration_valid,
    state.envelope_valid,
    state.provenance_valid,
    state.signature_valid,
    state.event_valid,
    state.freshness_valid,
  }

  action init: bool = s' = {
    phase: PHASE_RECEIVED,
    configuration_valid: true,
    envelope_valid: true,
    provenance_valid: true,
    signature_valid: true,
    event_valid: true,
    freshness_valid: true,
    outputs: 0,
    consumes: 0,
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
      freshness_valid:
        if (gate == GATE_FRESHNESS) false else s.freshness_valid,
    },
  }

  action verify: bool = all {
    s.phase == PHASE_RECEIVED,
    valid(s),
    s' = { ...s, phase: PHASE_VERIFIED, outputs: 1 },
  }

  action reject: bool = all {
    s.phase == PHASE_RECEIVED,
    not(valid(s)),
    s' = { ...s, phase: PHASE_REJECTED },
  }

  action consume: bool = all {
    s.phase == PHASE_VERIFIED,
    s.outputs == 1,
    s.consumes == 0,
    s' = { ...s, phase: PHASE_CONSUMED, consumes: 1 },
  }

  // Only the first consumption is modeled; durable provider event-id and
  // digest-bound idempotency is enforced downstream by fiducia-customer.rs.
  action retry: bool = all {
    Set(PHASE_VERIFIED, PHASE_REJECTED, PHASE_CONSUMED).contains(s.phase),
    s' = s,
  }

  action close: bool = all {
    s.phase != PHASE_CLOSED,
    s' = { ...s, phase: PHASE_CLOSED },
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

  val authentication_and_freshness_safety = and {
    Set(PHASE_RECEIVED, PHASE_VERIFIED, PHASE_REJECTED, PHASE_CONSUMED, PHASE_CLOSED).contains(s.phase),
    s.outputs >= 0,
    s.outputs <= 1,
    s.consumes >= 0,
    s.consumes <= 1,
    s.consumes <= s.outputs,
    (s.outputs == 1).implies(and {
      valid(s),
      Set(PHASE_VERIFIED, PHASE_CONSUMED, PHASE_CLOSED).contains(s.phase),
    }),
    (s.phase == PHASE_REJECTED).implies(and {
      s.outputs == 0,
      s.consumes == 0,
    }),
  }

  val verified_reached = s.outputs == 1
  val rejection_reached = s.phase == PHASE_REJECTED
  val consumption_reached = s.consumes == 1
}
