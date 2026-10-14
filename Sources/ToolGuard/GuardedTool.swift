import FoundationModels

/// Thrown by a guarded tool whose output type cannot carry a refusal message (anything but `String`).
public struct ToolGuardError: Error, Sendable, CustomStringConvertible {
    public var toolName: String
    public var reason: String
    public var description: String { "ToolGuard blocked \(toolName): \(reason)" }
}

/// A Foundation Models tool with the guard in front of it.
///
/// Before the wrapped tool runs, the guard checks the call against the policy and may ask the approver. A refused
/// call does not run; the model is told so in the tool's result (for `String` outputs), which lets it carry on
/// and explain, instead of the whole response failing. The tool's output is then filed under its source's trust.
public struct GuardedTool<Base: Tool>: Tool where Base.Arguments: Generable {
    public typealias Arguments = Base.Arguments
    public typealias Output = Base.Output

    private let base: Base
    private let spec: ToolSpec
    private let toolGuard: ToolGuard
    private let outputText: @Sendable (Base.Output) -> String
    private let refusal: @Sendable (String) throws -> Base.Output

    public var name: String { base.name }
    public var description: String { base.description }
    public var parameters: GenerationSchema { base.parameters }
    public var includesSchemaInInstructions: Bool { base.includesSchemaInInstructions }

    /// For tools that return a `String`.
    public init(_ base: Base, spec: ToolSpec, guard toolGuard: ToolGuard) where Base.Output == String {
        self.init(base, spec: spec, guard: toolGuard, outputText: { $0 }, refusal: { reason in
            "[ToolGuard] This action was not carried out: \(reason). Tell the user it needs their approval and do not retry it."
        })
    }

    /// For tools with any other output: say how to read it as text (for trust tracking). A refused call throws
    /// ``ToolGuardError`` unless you supply `refusal`.
    public init(
        _ base: Base, spec: ToolSpec, guard toolGuard: ToolGuard,
        outputText: @escaping @Sendable (Base.Output) -> String,
        refusal: (@Sendable (String) throws -> Base.Output)? = nil
    ) {
        let name = base.name
        self.base = base
        self.spec = spec
        self.toolGuard = toolGuard
        self.outputText = outputText
        self.refusal = refusal ?? { throw ToolGuardError(toolName: name, reason: $0) }
    }

    public func call(arguments: Base.Arguments) async throws -> Base.Output {
        let text = arguments.generatedContent.jsonString
        let verdict = await toolGuard.authorize(tool: base.name, spec: spec, arguments: text)
        guard verdict.allowed else { return try refusal(verdict.reason ?? "blocked by policy") }
        let output = try await base.call(arguments: arguments)
        await toolGuard.record(output: outputText(output), spec: spec)
        return output
    }
}

extension ToolGuard {
    /// Wraps a `String`-returning tool.
    public nonisolated func wrap<T: Tool>(_ tool: T, spec: ToolSpec) -> GuardedTool<T>
    where T.Arguments: Generable, T.Output == String {
        GuardedTool(tool, spec: spec, guard: self)
    }

    /// Wraps a tool with any output type.
    public nonisolated func wrap<T: Tool>(
        _ tool: T, spec: ToolSpec,
        outputText: @escaping @Sendable (T.Output) -> String,
        refusal: (@Sendable (String) throws -> T.Output)? = nil
    ) -> GuardedTool<T> where T.Arguments: Generable {
        GuardedTool(tool, spec: spec, guard: self, outputText: outputText, refusal: refusal)
    }
}
