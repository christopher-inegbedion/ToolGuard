import Foundation

/// Cheap, deterministic text matching: has text that arrived from one place turned up in another?
/// There is no model in this, which is the point: an attacker cannot talk it out of its answer.
///
/// Two signals:
/// - **Rare tokens**: email addresses, URLs and long numbers. These are what an attacker needs verbatim
///   (where to send, where to fetch) and they are rarely re-worded.
/// - **Word 4-grams**: four words in a row. Catches copied sentences.
///
/// Paraphrased text slips past both. That is a real limit; the session-level rules in ``Policy`` exist
/// because of it.
struct TextFingerprint: Sendable {
    private(set) var rareTokens: Set<String> = []
    private(set) var ngrams: Set<String> = []

    static let n = 4

    init() {}

    init(_ text: String) { add(text) }

    var isEmpty: Bool { rareTokens.isEmpty && ngrams.isEmpty }

    mutating func add(_ text: String) {
        rareTokens.formUnion(Self.rareTokens(in: text))
        ngrams.formUnion(Self.ngrams(in: text))
    }

    /// What `text` shares with this fingerprint, as short human-readable evidence.
    func overlap(with text: String, excluding trusted: TextFingerprint? = nil) -> [String] {
        var evidence: [String] = []
        for token in Self.rareTokens(in: text) where rareTokens.contains(token) && !(trusted?.rareTokens.contains(token) ?? false) {
            evidence.append(token)
        }
        let words = Self.words(in: text)
        if words.count >= Self.n {
            for i in 0...(words.count - Self.n) {
                let gram = words[i..<(i + Self.n)].joined(separator: " ")
                if ngrams.contains(gram), !(trusted?.ngrams.contains(gram) ?? false) {
                    evidence.append("“\(gram)…”")
                    if evidence.count >= 3 { break }
                }
            }
        }
        return Array(evidence.prefix(3))
    }

    // MARK: Extraction

    /// Words for phrase matching. Addresses, URLs and numbers are removed first: they are matched whole as rare
    /// tokens, and counting their pieces again as phrases would report one match twice.
    static func words(in text: String) -> [String] {
        var plain = text
        for regex in patterns {
            // match against the string as it is now: each replacement shortens it
            let matches = regex.matches(in: plain, range: NSRange(plain.startIndex..., in: plain))
            for match in matches.reversed() {
                if let r = Range(match.range, in: plain) { plain.replaceSubrange(r, with: " ") }
            }
        }
        return plain.lowercased().split { !($0.isLetter || $0.isNumber) }.map(String.init)
    }

    static func ngrams(in text: String) -> Set<String> {
        let words = words(in: text)
        guard words.count >= n else { return [] }
        return Set((0...(words.count - n)).map { words[$0..<($0 + n)].joined(separator: " ") })
    }

    private static let patterns: [NSRegularExpression] = [
        #"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+"#,    // email address
        #"https?://[^\s"'<>)\]]+"#,                                     // URL
        #"(?<![A-Za-z0-9])\+?\d[\d\-\s().]{6,}\d"#,                     // phone-like number
    ].compactMap { try? NSRegularExpression(pattern: $0) }

    static func rareTokens(in text: String) -> Set<String> {
        var out = Set<String>()
        let range = NSRange(text.startIndex..., in: text)
        for regex in patterns {
            for match in regex.matches(in: text, range: range) {
                if let r = Range(match.range, in: text) {
                    out.insert(normalize(String(text[r])))
                }
            }
        }
        return out
    }

    private static func normalize(_ token: String) -> String {
        var t = token.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".,;:!?\"'"))
        if t.first?.isNumber == true || t.first == "+" { t = t.filter { $0.isNumber } }  // phone numbers: digits only
        return t
    }
}
