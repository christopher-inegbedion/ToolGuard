import FoundationModels

/// A `LanguageModelSession` whose prompts are registered as trusted and whose tools are guarded.
///
/// ```swift
/// let guardian = ToolGuard(approver: { request in await ui.confirm(request.reason) })
/// let session = GuardedSession(
///     guard: guardian,
///     tools: [guardian.wrap(ReadEmail(), spec: .init(outputTrust: .untrusted)),
///             guardian.wrap(SendMessage(), spec: .init(effects: .sendsExternally))],
///     instructions: "You help with the user's mail.")
/// let answer = try await session.respond(to: "Summarise my newest email")
/// ```
public final class GuardedSession: Sendable {
    public let session: LanguageModelSession
    public let toolGuard: ToolGuard

    public init(
        guard toolGuard: ToolGuard,
        tools: [any Tool],
        instructions: String? = nil,
        model: SystemLanguageModel = .default
    ) async {
        self.toolGuard = toolGuard
        self.session = LanguageModelSession(model: model, tools: tools, instructions: instructions)
        if let instructions { await toolGuard.trust(instructions) }
    }

    /// Registers the prompt as the user's own words, then asks the model.
    @discardableResult
    public func respond(to prompt: String, options: GenerationOptions = GenerationOptions()) async throws -> String {
        await toolGuard.trust(prompt)
        return try await session.respond(to: prompt, options: options).content
    }
}
