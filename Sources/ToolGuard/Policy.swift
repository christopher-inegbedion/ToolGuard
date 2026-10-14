/// The verdict on one tool call.
public enum GuardDecision: Sendable, Equatable {
    case allow
    /// The call needs a human yes first. The reason is shown to the approver.
    case requireApproval(reason: String)
    /// The call never runs.
    case deny(reason: String)

    public var isAllowed: Bool { self == .allow }

    var reason: String? {
        switch self {
        case .allow: nil
        case .requireApproval(let r), .deny(let r): r
        }
    }

    /// Stricter wins: deny > requireApproval > allow.
    func merged(with other: GuardDecision) -> GuardDecision {
        switch (self, other) {
        case (.deny, _): self
        case (_, .deny): other
        case (.requireApproval, _): self
        case (_, .requireApproval): other
        default: .allow
        }
    }
}

/// What the guard asks a human (or your UI) before it lets a risky call run.
public struct ApprovalRequest: Sendable {
    public var toolName: String
    public var arguments: String
    public var reason: String

    public init(toolName: String, arguments: String, reason: String) {
        self.toolName = toolName
        self.arguments = arguments
        self.reason = reason
    }
}

/// Asked before a call that needs approval runs. The default approver says no, so an app that forgets to
/// supply one fails closed.
public typealias Approver = @Sendable (ApprovalRequest) async -> Bool

/// The rules. Every rule is deterministic: no model decides anything here.
public struct Policy: Sendable {
    /// What to do once the model has read untrusted content and then asks for a side effect, whatever its arguments.
    /// Catches the attacks that re-word the injected text, which the matching rules cannot see.
    public var afterUntrustedContent: Response
    /// What to do when a side-effecting call's arguments contain text copied from untrusted content
    /// (an address, a URL, a sentence).
    public var untrustedArguments: Response
    /// What to do when a call that sends data out contains private data the user did not type.
    public var privateDataEgress: Response
    /// The "lethal trifecta": private data, untrusted content and a way out are all present in one session.
    public var trifecta: Response
    /// Side effects that always need approval, even with nothing suspicious.
    public var alwaysConfirm: ToolEffects

    public enum Response: Sendable, Equatable {
        case allow, requireApproval, deny
    }

    public init(
        afterUntrustedContent: Response = .requireApproval,
        untrustedArguments: Response = .requireApproval,
        privateDataEgress: Response = .requireApproval,
        trifecta: Response = .requireApproval,
        alwaysConfirm: ToolEffects = .none
    ) {
        self.afterUntrustedContent = afterUntrustedContent
        self.untrustedArguments = untrustedArguments
        self.privateDataEgress = privateDataEgress
        self.trifecta = trifecta
        self.alwaysConfirm = alwaysConfirm
    }

    /// Ask a human whenever untrusted content may be steering a side effect, or private data is leaving.
    public static let standard = Policy()
    /// Also ask before every side effect.
    public static let strict = Policy(alwaysConfirm: .sideEffects)
    /// Never allow the dangerous combinations: no approval path.
    public static let denyDangerous = Policy(afterUntrustedContent: .deny, untrustedArguments: .deny,
                                             privateDataEgress: .deny, trifecta: .deny)
    /// Only the exact-match rules: no session-level suspicion. Fewer prompts, weaker against paraphrased attacks.
    public static let matchingOnly = Policy(afterUntrustedContent: .allow)
}

extension Policy.Response {
    func decision(_ reason: String) -> GuardDecision {
        switch self {
        case .allow: .allow
        case .requireApproval: .requireApproval(reason: reason)
        case .deny: .deny(reason: reason)
        }
    }
}
