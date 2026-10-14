/// What the session has seen, by source. Text is filed under exactly one kind of trust.
struct TrustLedger: Sendable {
    /// Text the user or the app wrote: prompts, instructions. Matching text is excused from suspicion.
    private(set) var trusted = TextFingerprint()
    /// Text from outside: emails, web pages, documents.
    private(set) var untrusted = TextFingerprint()
    /// Text from tools that read private data.
    private(set) var privateData = TextFingerprint()

    private(set) var sawUntrusted = false
    private(set) var sawPrivate = false

    mutating func addTrusted(_ text: String) { trusted.add(text) }

    mutating func addToolOutput(_ text: String, spec: ToolSpec) {
        if spec.outputTrust == .untrusted {
            untrusted.add(text)
            sawUntrusted = true
        }
        if spec.effects.contains(.readsPrivateData) {
            privateData.add(text)
            sawPrivate = true
        }
    }
}

/// The decision logic, pure: a ledger snapshot, a tool and its arguments in; a decision out. No model, no I/O,
/// so it can be tested exhaustively.
struct PolicyEngine: Sendable {
    var policy: Policy

    func evaluate(tool: String, spec: ToolSpec, arguments: String, ledger: TrustLedger) -> GuardDecision {
        var decision = GuardDecision.allow
        let risky = !spec.effects.intersection(.sideEffects).isEmpty

        if !spec.effects.intersection(policy.alwaysConfirm).isEmpty {
            decision = decision.merged(with: .requireApproval(reason: "\(tool) changes things outside the app"))
        }

        guard risky else { return decision }

        // Text copied from untrusted content into a side effect.
        let copied = ledger.untrusted.overlap(with: arguments, excluding: ledger.trusted)
        if !copied.isEmpty {
            decision = decision.merged(with: policy.untrustedArguments.decision(
                "\(tool) was given text taken from untrusted content: \(copied.joined(separator: ", "))"))
        }

        // Private data leaving the device.
        if spec.effects.contains(.sendsExternally) {
            let leaking = ledger.privateData.overlap(with: arguments, excluding: ledger.trusted)
            if !leaking.isEmpty {
                decision = decision.merged(with: policy.privateDataEgress.decision(
                    "\(tool) would send private data off the device: \(leaking.joined(separator: ", "))"))
            }
            if ledger.sawUntrusted && ledger.sawPrivate {
                decision = decision.merged(with: policy.trifecta.decision(
                    "this session has read private data and untrusted content, and \(tool) can send data out"))
            }
        }

        // The model has read content from outside and now wants to change something.
        if ledger.sawUntrusted {
            decision = decision.merged(with: policy.afterUntrustedContent.decision(
                "\(tool) was requested after the model read untrusted content"))
        }
        return decision
    }
}
