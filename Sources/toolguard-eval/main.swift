import Foundation
import ToolGuard
import ToolGuardEval

// toolguard-eval [--trials N] [--modes baseline,firewall,...] [--only A01,N02] [--attacks|--benign]
//                [--temperature T] [--json file] [--markdown file] [--list] [--simulate]

func value(_ flag: String) -> String? {
    guard let i = CommandLine.arguments.firstIndex(of: flag), i + 1 < CommandLine.arguments.count else { return nil }
    return CommandLine.arguments[i + 1]
}
func has(_ flag: String) -> Bool { CommandLine.arguments.contains(flag) }

var scenarios = Corpus.all
if has("--attacks") { scenarios = Corpus.attacks }
if has("--benign") { scenarios = Corpus.benign }
if let only = value("--only") { let ids = Set(only.split(separator: ",").map(String.init)); scenarios = scenarios.filter { ids.contains($0.id) } }

if has("--list") {
    for s in scenarios { print("\(s.id)  \(s.category.padding(toLength: 20, withPad: " ", startingAt: 0)) \(s.userPrompt)") }
    exit(0)
}

if has("--simulate") {
    // No model: a fooled model's calls against each policy.
    for (name, policy) in [("no protection", nil), ("matching-only", Policy.matchingOnly), ("firewall", Policy.standard)] as [(String, Policy?)] {
        var leaked = 0
        for s in scenarios where s.kind == .attack {
            if await Simulation.run(s, policy: policy).sideEffects { leaked += 1; print("  \(name): \(s.id) got through") }
        }
        print("\(name): \(leaked) of \(scenarios.filter { $0.kind == .attack }.count) simulated attacks caused a side effect")
    }
    exit(0)
}

let trials = Int(value("--trials") ?? "") ?? 3
let temperature = Double(value("--temperature") ?? "") ?? 0.7
var modes = Mode.allCases
if let m = value("--modes") { modes = m.split(separator: ",").compactMap { Mode(rawValue: String($0)) } }

print("Running \(scenarios.count) scenarios × \(modes.count) modes × \(trials) trials = \(scenarios.count * modes.count * trials) runs on the on-device model…")
let started = Date()
nonisolated(unsafe) var done = 0
let total = scenarios.count * modes.count * trials
let results = await Evaluator.run(scenarios: scenarios, modes: modes, trials: trials, temperature: temperature) { r in
    done += 1
    if done % 20 == 0 || done == total { print("  \(done)/\(total) (\(Int(Date().timeIntervalSince(started)))s)") }
}
let markdown = Report.markdown(results)
print("\n" + markdown)
if let path = value("--markdown") { try markdown.write(toFile: path, atomically: true, encoding: .utf8) }
if let path = value("--json") {
    let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
    try enc.encode(results).write(to: URL(fileURLWithPath: path))
}
