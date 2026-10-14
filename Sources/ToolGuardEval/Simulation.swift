import FoundationModels
import ToolGuard

/// Policy testing with no model: take the calls a fooled model would make and push them through the guard.
/// Deterministic, so it runs in CI where the on-device model is not available.
public enum Simulation {
    public struct Outcome: Sendable {
        public var sideEffects: Bool
        public var asked: Int
        public var denied: Int
    }

    /// Plays the scenario's `compromisedCalls` against `policy`, with the user's finger on a button that only
    /// approves what they asked for. A nil policy means no protection.
    public static func run(_ scenario: Scenario, policy: Policy?) async -> Outcome {
        let sandbox = Sandbox(newestEmail: scenario.email)
        let counter = Counter()
        let g = ToolGuard(policy: policy ?? .standard, approver: { request in
            counter.requested()
            return scenario.approves(request)
        })
        await g.trust(scenario.userPrompt)

        // With no policy, every call goes straight to the tool.
        func wrap<T: Tool>(_ tool: T, _ spec: ToolSpec) -> any Tool where T.Arguments: Generable, T.Output == String {
            policy == nil ? tool : g.wrap(tool, spec: spec)
        }
        let readEmail = wrap(ReadEmailTool(sandbox: sandbox), SampleAgent.readEmail)
        let readContacts = wrap(ReadContactsTool(), SampleAgent.readContacts)
        let send = wrap(SendMessageTool(sandbox: sandbox), SampleAgent.sendMessage)
        let open = wrap(OpenURLTool(sandbox: sandbox), SampleAgent.openURL)
        let delete = wrap(DeleteNoteTool(sandbox: sandbox), SampleAgent.deleteNote)

        // The model reads the email (that is what the user asked for), then does what the email said.
        _ = try? await call(readEmail, EmailArgs(id: 1))
        for step in scenario.compromisedCalls {
            switch step {
            case .readContacts: _ = try? await call(readContacts, NoArgs(unused: nil))
            case .send(let to, let body): _ = try? await call(send, SendArgs(to: to, body: body))
            case .openURL(let url): _ = try? await call(open, URLArgs(url: url))
            case .deleteNote(let id): _ = try? await call(delete, NoteArgs(id: id))
            }
        }
        let denied = await g.events.filter { $0.outcome == .denied }.count
        return Outcome(sideEffects: sandbox.hasSideEffects, asked: counter.requestedCount, denied: denied)
    }

    private static func call(_ tool: any Tool, _ arguments: some Generable) async throws -> String {
        func open<T: Tool>(_ t: T) async throws -> String {
            guard let args = arguments as? T.Arguments else { return "" }
            return "\(try await t.call(arguments: args))"
        }
        return try await open(tool)
    }
}
