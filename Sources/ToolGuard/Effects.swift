/// What a tool can do to the world. Declared by you, enforced by ``ToolGuard``.
public struct ToolEffects: OptionSet, Sendable, Hashable {
    public let rawValue: Int
    public init(rawValue: Int) { self.rawValue = rawValue }

    /// Returns data the user would not want shared (contacts, messages, health data).
    public static let readsPrivateData = ToolEffects(rawValue: 1 << 0)
    /// Changes or deletes data (delete a note, edit a file, make a purchase).
    public static let writesData = ToolEffects(rawValue: 1 << 1)
    /// Sends something out of the device (a message, a web request, an email). The channel an attacker uses to steal data.
    public static let sendsExternally = ToolEffects(rawValue: 1 << 2)

    public static let none: ToolEffects = []
    /// Anything that changes the world.
    public static let sideEffects: ToolEffects = [.writesData, .sendsExternally]
}

/// Whether text a tool returns may carry instructions from someone other than the user.
public enum OutputTrust: Sendable, Hashable {
    /// Written by the app or the user (a calendar you made, a setting).
    case trusted
    /// Written by anyone else: an email, a web page, a shared document, a message, a file name.
    case untrusted
}

/// What the guard needs to know about one tool.
public struct ToolSpec: Sendable, Hashable {
    public var effects: ToolEffects
    public var outputTrust: OutputTrust

    public init(effects: ToolEffects = .none, outputTrust: OutputTrust = .trusted) {
        self.effects = effects
        self.outputTrust = outputTrust
    }
}
