import Foundation

/// One entry in the audit log.
public struct GuardEvent: Sendable, Equatable {
    public enum Outcome: Sendable, Equatable { case allowed, approved, declined, denied }
    public var toolName: String
    public var outcome: Outcome
    public var reason: String?
    public var arguments: String
}

/// Shared state for one conversation: what the session has read, the policy, and who to ask.
///
/// Create one per `LanguageModelSession`, wrap that session's tools with ``wrap(_:spec:)``, and tell it about
/// the user's own words with ``trust(_:)``. Tool results are filed automatically.
public actor ToolGuard {
    private var ledger = TrustLedger()
    private var engine: PolicyEngine
    private let approver: Approver
    private var log: [GuardEvent] = []

    public init(policy: Policy = .standard, approver: @escaping Approver = { _ in false }) {
        self.engine = PolicyEngine(policy: policy)
        self.approver = approver
    }

    public var policy: Policy {
        get { engine.policy }
        set { engine.policy = newValue }
    }

    /// The audit log: every guarded call and what happened to it.
    public var events: [GuardEvent] { log }

    /// Text the user wrote (their prompt). Matching text in a tool's arguments is not suspicious.
    public func trust(_ text: String) { ledger.addTrusted(text) }

    /// The verdict a call would get right now, without running anything.
    public func evaluate(tool: String, spec: ToolSpec, arguments: String) -> GuardDecision {
        engine.evaluate(tool: tool, spec: spec, arguments: arguments, ledger: ledger)
    }

    /// Decides, asks if needed, and records. Returns whether the call may run.
    func authorize(tool: String, spec: ToolSpec, arguments: String) async -> (allowed: Bool, reason: String?) {
        let decision = evaluate(tool: tool, spec: spec, arguments: arguments)
        switch decision {
        case .allow:
            log.append(GuardEvent(toolName: tool, outcome: .allowed, reason: nil, arguments: arguments))
            return (true, nil)
        case .deny(let reason):
            log.append(GuardEvent(toolName: tool, outcome: .denied, reason: reason, arguments: arguments))
            return (false, reason)
        case .requireApproval(let reason):
            let yes = await approver(ApprovalRequest(toolName: tool, arguments: arguments, reason: reason))
            log.append(GuardEvent(toolName: tool, outcome: yes ? .approved : .declined, reason: reason, arguments: arguments))
            return (yes, reason)
        }
    }

    /// Files a tool's result under the trust of its source.
    func record(output: String, spec: ToolSpec) { ledger.addToolOutput(output, spec: spec) }
}
