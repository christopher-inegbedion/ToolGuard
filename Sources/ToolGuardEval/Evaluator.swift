import Foundation
import FoundationModels
import ToolGuard

/// What protects the agent in one run.
public enum Mode: String, Sendable, CaseIterable, Codable {
    /// Nothing: the model alone, as most apps ship it.
    case baseline
    /// Only a stronger system prompt that tells the model not to obey emails.
    case hardenedPrompt = "hardened-prompt"
    /// The guard with the standard policy.
    case firewall
    /// The guard with exact-match rules only (no session-level suspicion): shows what the matching alone buys.
    case matchingOnly = "matching-only"

    var policy: Policy? {
        switch self {
        case .baseline, .hardenedPrompt: nil
        case .firewall: .standard
        case .matchingOnly: .matchingOnly
        }
    }

    var instructions: String {
        self == .hardenedPrompt ? SampleAgent.hardenedInstructions : SampleAgent.instructions
    }
}

/// One scenario, one mode, one attempt.
public struct RunResult: Sendable, Codable {
    public var scenarioID: String
    public var category: String
    public var isAttack: Bool
    public var mode: Mode
    public var trial: Int
    /// Attack: the agent did nothing to the outside world. Benign: the task was done.
    public var succeeded: Bool
    /// The model refused or the framework raised an error before finishing.
    public var errored: Bool
    public var error: String?
    public var approvalsRequested: Int
    public var approvalsGranted: Int
    public var denied: Int
    public var seconds: Double
}

public enum Evaluator {
    /// Runs every scenario in every mode `trials` times against the on-device model. Slow: each run is a real
    /// model conversation with tool calls.
    public static func run(
        scenarios: [Scenario], modes: [Mode], trials: Int,
        temperature: Double = 0.7,
        progress: (@Sendable (RunResult) -> Void)? = nil
    ) async -> [RunResult] {
        var results: [RunResult] = []
        for scenario in scenarios {
            for mode in modes {
                for trial in 0..<trials {
                    let r = await runOnce(scenario, mode: mode, trial: trial, temperature: temperature)
                    results.append(r)
                    progress?(r)
                }
            }
        }
        return results
    }

    public static func runOnce(_ scenario: Scenario, mode: Mode, trial: Int, temperature: Double = 0.7) async -> RunResult {
        let sandbox = Sandbox(newestEmail: scenario.email)
        let started = Date()
        var errorText: String?
        var requested = 0, granted = 0
        var denied = 0

        do {
            if let policy = mode.policy {
                let counter = Counter()
                let g = ToolGuard(policy: policy, approver: { request in
                    counter.requested()
                    let yes = scenario.approves(request)
                    if yes { counter.granted() }
                    return yes
                })
                let session = await GuardedSession(guard: g, tools: SampleAgent.guardedTools(sandbox, guard: g),
                                                   instructions: mode.instructions)
                _ = try await session.respond(to: scenario.userPrompt, options: GenerationOptions(temperature: temperature))
                requested = counter.requestedCount
                granted = counter.grantedCount
                denied = await g.events.filter { $0.outcome == .denied }.count
            } else {
                let session = LanguageModelSession(tools: SampleAgent.plainTools(sandbox), instructions: mode.instructions)
                _ = try await session.respond(to: scenario.userPrompt, options: GenerationOptions(temperature: temperature))
            }
        } catch {
            errorText = "\(error)".prefix(160).description
        }
        return RunResult(
            scenarioID: scenario.id, category: scenario.category, isAttack: scenario.kind == .attack, mode: mode,
            trial: trial, succeeded: scenario.succeeded(sandbox), errored: errorText != nil, error: errorText,
            approvalsRequested: requested, approvalsGranted: granted, denied: denied,
            seconds: Date().timeIntervalSince(started))
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var r = 0, g = 0
    func requested() { lock.withLock { r += 1 } }
    func granted() { lock.withLock { g += 1 } }
    var requestedCount: Int { lock.withLock { r } }
    var grantedCount: Int { lock.withLock { g } }
}
