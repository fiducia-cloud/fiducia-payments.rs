module provider_verification_test {
  import provider_verification.* from "./provider_verification"

  run validStripeVerifiesAndConsumesTest =
    init_with_provider(PROVIDER_STRIPE)
      .then(verify)
      .then(consume)
      .expect(and {
        s.phase == PHASE_CONSUMED,
        s.outputs == 1,
        s.consumes == 1,
        authentication_safety,
      })

  run validPaypalVerifiesAndConsumesTest =
    init_with_provider(PROVIDER_PAYPAL)
      .then(verify)
      .then(consume)
      .expect(and {
        s.phase == PHASE_CONSUMED,
        s.outputs == 1,
        s.consumes == 1,
        authentication_safety,
      })

  run invalidConfigurationRejectsTest =
    init_with_provider(PROVIDER_STRIPE)
      .then(invalidate(GATE_CONFIGURATION))
      .then(reject)
      .expect(and {
        s.phase == PHASE_REJECTED,
        s.outputs == 0,
        authentication_safety,
      })

  run invalidEnvelopeRejectsTest =
    init_with_provider(PROVIDER_PAYPAL)
      .then(invalidate(GATE_ENVELOPE))
      .then(reject)
      .expect(and {
        s.phase == PHASE_REJECTED,
        s.outputs == 0,
        authentication_safety,
      })

  run invalidProvenanceRejectsTest =
    init_with_provider(PROVIDER_PAYPAL)
      .then(invalidate(GATE_PROVENANCE))
      .then(reject)
      .expect(and {
        s.phase == PHASE_REJECTED,
        s.outputs == 0,
        authentication_safety,
      })

  run signatureMismatchRejectsTest =
    init_with_provider(PROVIDER_STRIPE)
      .then(invalidate(GATE_SIGNATURE))
      .then(reject)
      .expect(and {
        s.phase == PHASE_REJECTED,
        s.outputs == 0,
        authentication_safety,
      })

  run malformedEventRejectsTest =
    init_with_provider(PROVIDER_PAYPAL)
      .then(invalidate(GATE_EVENT))
      .then(reject)
      .expect(and {
        s.phase == PHASE_REJECTED,
        s.outputs == 0,
        authentication_safety,
      })

  run consumeBeforeVerifyFailsTest =
    init_with_provider(PROVIDER_STRIPE)
      .then(consume)
      .fail()

  run secondVerificationFailsTest =
    init_with_provider(PROVIDER_STRIPE)
      .then(verify)
      .then(verify)
      .fail()

  run secondConsumeFailsTest =
    init_with_provider(PROVIDER_PAYPAL)
      .then(verify)
      .then(consume)
      .then(consume)
      .fail()

  run retryAfterVerificationIsNoOpTest =
    init_with_provider(PROVIDER_STRIPE)
      .then(verify)
      .then(retry)
      .expect(and {
        s.phase == PHASE_VERIFIED,
        s.outputs == 1,
        s.consumes == 0,
        authentication_safety,
      })

  run closeBlocksVerificationTest =
    init_with_provider(PROVIDER_PAYPAL)
      .then(close)
      .then(verify)
      .fail()
}
