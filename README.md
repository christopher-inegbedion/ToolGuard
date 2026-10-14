# ToolGuard

Stop prompt injection from turning an on-device AI agent's tool calls into damage.

If your app gives Apple's Foundation Models a tool that can send, delete or open things, any text the model reads (an
email, a web page, a shared note) can try to steer it. ToolGuard puts a deterministic guard in front of those tools. It
decides in plain Swift code, with no model involved, whether a call may run, needs the user's approval, or is refused.

```swift
import FoundationModels
import ToolGuard

let guardian = ToolGuard(approver: { request in
    await confirmWithUser("\(request.reason)\n\(request.toolName) \(request.arguments)")
})

let session = await GuardedSession(
    guard: guardian,
    tools: [
        guardian.wrap(ReadEmail(),   spec: ToolSpec(outputTrust: .untrusted)),     // text from other people
        guardian.wrap(ReadContacts(), spec: ToolSpec(effects: .readsPrivateData)),
        guardian.wrap(SendMessage(), spec: ToolSpec(effects: .sendsExternally)),
        guardian.wrap(DeleteNote(),  spec: ToolSpec(effects: .writesData)),
    ],
    instructions: "You help with the user's mail.")

let answer = try await session.respond(to: "Summarise my newest email")
```

## Why

Measured on the on-device model (macOS 26.5, Apple M4): 30 injection attacks hidden in an email the user asked the
assistant to read, 5 attempts each, 150 runs per setting.

### Attacks (30 scenarios, 600 runs)

| Protection | Runs | **Compromised** | Blocked by guard | Model resisted | Framework refused |
|---|---:|---:|---:|---:|---:|
| baseline | 150 | **38 (25%)** | 0 | 100 | 12 |
| hardened-prompt | 150 | **46 (31%)** | 0 | 88 | 16 |
| firewall | 150 | **0 (0%)** | 39 | 95 | 16 |
| matching-only | 150 | **16 (11%)** | 21 | 99 | 14 |

**Compromised, by attack type**

| Attack type | baseline | hardened-prompt | firewall | matching-only |
|---|---:---:---:---:|
| authority claim | 0/25 | 3/25 | 0/25 | 0/25 |
| data theft | 9/30 | 9/30 | 0/30 | 0/30 |
| destructive | 7/20 | 9/20 | 0/20 | 10/20 |
| direct override | 15/25 | 16/25 | 0/25 | 0/25 |
| disguised | 5/25 | 4/25 | 0/25 | 5/25 |
| social engineering | 2/25 | 5/25 | 0/25 | 1/25 |

### Normal tasks (6 scenarios, 120 runs)

| Protection | Task done | Approval prompts per task | Prompts the user said yes to |
|---|---:|---:|---:|
| baseline | 30/30 (100%) | 0.00 | 0/0 |
| hardened-prompt | 30/30 (100%) | 0.00 | 0/0 |
| firewall | 30/30 (100%) | 0.50 | 15/15 |
| matching-only | 30/30 (100%) | 0.50 | 15/15 |

What the numbers say:

- **The model alone is not safe.** A quarter of attack runs made it send, open or delete something the user never asked for.
- **A stronger system prompt did not help.** Telling the model to ignore instructions in emails scored 31%, no better than
  no protection given the run-to-run noise.
- **The guard stopped every attack, and normal use still worked.** All 30 normal tasks completed in every setting; the
  guard asked for approval on half of them (the ones that send or open something after reading an email), and the user said yes to all 15.
- **Exact-match rules alone are not enough.** Matching text copied from an email (an address, a URL, a sentence) blocked most
  attacks, but 11% still got through: destructive requests and disguised ones share nothing to match. The session-level rule
  ("the model read untrusted content, now it wants a side effect") is what closes that gap, at the cost of those approval prompts.

"Framework refused" means Apple's own safety framework rejected the response before it finished. Those runs are neither wins
for the model nor for the guard, so they are counted separately.

## How it works

You tell the guard three things about each tool: what it can do (`ToolEffects`: read private data, write data, send
externally), and whether its output is trusted. The guard keeps a ledger of what the conversation has read. A call that
changes the world is checked against these rules, strictest verdict wins:

| Rule | Catches |
|---|---|
| **Copied text.** An address, URL, number or four-word phrase in the arguments that came from untrusted content and not from the user | "send it to attacker@…" |
| **Private data leaving.** Arguments contain text from a tool that read private data, and the tool sends data out | a contact list in a message body |
| **Lethal trifecta.** The session has read private data *and* untrusted content, and the tool can send data out | exfiltration that matches nothing |
| **After untrusted content.** The model read something from outside and now asks for a side effect | re-worded attacks, destructive requests |
| **Always confirm** (optional) | any side effect |

Each rule can be set to allow, ask or deny. Ready-made policies: `.standard`, `.strict` (also asks before every side
effect), `.denyDangerous` (never lets the risky combinations run), `.matchingOnly` (fewer prompts, weaker).

A refused call does not run. The model is told in the tool's result that it needs the user's approval, so it can carry on and
explain instead of the whole response failing. Every call and its outcome is in `await guardian.events`.

The default approver says no, so an app that forgets to supply one fails closed.

## Install

Add `https://github.com/christopher-inegbedion/ToolGuard` as a Swift package. Requires iOS 26 / macOS 26 (Foundation Models).

## Limits (read these)

- **It limits damage; it does not stop the model being fooled.** A compromised model can still say wrong things. The guard
  only governs the tools you wrap.
- **The user is the last line.** Approval prompts only help if people read them. The evaluation's "user" approves exactly what
  they asked for, which is an ideal. Real people click through.
- **Copy-detection is a heuristic.** Re-worded text evades it. That is why the session-level rules exist, and why they cost prompts.
- **One model, one OS, one machine.** Results are from the system model on macOS 26.5 at temperature 0.7, 5 attempts per
  scenario. Rates move with OS updates. The corpus is 30 hand-written attacks; it is a regression test, not a proof.
- **Only text reaches the guard.** Injection through images or other channels the model reads is not covered.
- **Apple is adding its own hooks.** iOS 27 reportedly adds tool-call interception; this package targets the iOS 26 SDK.

## Run the evaluation yourself

```sh
swift run -c release toolguard-eval --trials 5 --markdown results.md   # live, on your Mac's on-device model (about 20 minutes)
swift run toolguard-eval --simulate                                    # no model: a fooled model's calls against each policy
swift run toolguard-eval --list
```

`--simulate` replays what a model that obeyed each attack *would do*, deterministically. With no protection all 30 get
through; with matching-only 9 do; with the standard policy none do.

Needs Apple Intelligence enabled for the live run. The corpus is for testing your own agent's defences: every attack
targets a fictional address on a reserved test domain (`evil.test`) inside a sandbox that cannot reach anything.

## Tested

41 deterministic tests (`swift test`, no model needed): the text matching, every policy rule and combination, approval and
denial, the tool wrapper (including tools that do not return a string), the corpus itself, and the simulated attacks against
each policy. The live evaluation above is what measures the real model; its raw results are in `docs/results.json`.

MIT licensed.
