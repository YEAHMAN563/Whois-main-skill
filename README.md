# Reverse Master

**Reverse Master** is a workflow skill for evidence-driven native-binary reverse engineering. It helps an AI assistant plan and carry out authorized analysis of PE, ELF, and Mach-O binaries, choose suitable tools, recover program behavior, and produce structured technical and security reports.

It is designed as an analysis workflow—not as a promise that every binary can be fully unpacked, deobfuscated, or devirtualized. Results depend on the sample, available tooling, analysis environment, and evidence that can be collected.

## What it covers

- **Binary triage:** file identity, architecture, sections/segments, entry points, imports, strings, entropy, and likely runtime/compiler clues.
- **Packing and protection analysis:** wrapper identification, layer mapping, static-first unpacking, OEP investigation, and validation of recovered images.
- **Deobfuscation:** control-flow flattening, opaque predicates, junk/dead code, indirect control flow, hidden strings/constants, and API/import resolution.
- **Devirtualization:** virtualization-model identification, VM handler analysis, intermediate representations, control-flow recovery, and semantic validation.
- **Anti-analysis review:** identify anti-debugging, anti-VM, anti-tamper, and integrity checks in an authorized, controlled analysis context.
- **Native-code analysis:** function-level behavior, data flow, calling conventions, platform/runtime quirks, and cross-references.
- **IDA Pro workflow:** database-first analysis, disassembly/decompiler cross-checks, scripting discipline, checkpoints, and optional MCP-bridge use when available.
- **Tool coordination:** select tools based on the task, preserve provenance, use bounded automation, and verify each stage.
- **Reporting:** structured `security.md`, evidence/confidence labels, unresolved questions, and optional Obsidian knowledge notes.

## Source reconstruction is opt-in

The skill does **not** automatically turn a binary into C or C++. Reconstructed source is approximate and may not match the original source code. It is only attempted when the user explicitly requests source reconstruction, and any output must be labeled according to what was actually recovered (for example, pseudocode, lifted representation, or approximate C-like code).

## Repository contents

| Path | Purpose |
| --- | --- |
| `SKILL.md` | Main workflow and operating instructions for the assistant. |
| `README.md` | Project overview, scope, setup notes, and usage guidance. |
| `LICENSE` | MIT license text. |
| `.gitignore` | Common local analysis artifacts to keep out of commits. |
| `CONTRIBUTING.md` | Guidance for proposing corrections and improvements. |
| `SECURITY.md` | Responsible-use and safe-handling policy. |

## How to use

1. Add or install this skill in the AI tool or agent environment that supports `SKILL.md`-style instructions. The exact installation location depends on that platform.
2. Make the skill available to the assistant before starting a binary-analysis task.
3. Provide the binary or analysis artifacts and state the goal: identify, unpack, analyze behavior, deobfuscate, devirtualize, or write a security report.
4. State the authorization and relevant scope. Analyze only software you own or are authorized to examine.
5. Ask for source reconstruction explicitly if you need it; it is intentionally not the default.

### Example requests

- “Triage this PE and explain its structure, imports, strings, and likely protections.”
- “Analyze this authorized sample and produce a `security.md` report with observed, inferred, and verified findings separated.”
- “Determine whether this binary is packed or virtualized, and document the evidence.”
- “Recover the control-flow graph and explain the obfuscation transformations.”
- “Devirtualize the relevant function into an intermediate representation; do not generate C++.”
- “Reconstruct approximate C++ for the selected function.”

## Tooling

The skill is tool-agnostic, with an **IDA Pro-centered workflow when IDA is available**. Depending on the task and installation, an analysis environment may also use PE/ELF/Mach-O parsers, disassemblers, decompilers, debuggers, emulators, and format-specific utilities. The skill instructs the assistant to discover available tools and verify versions/capabilities rather than assuming a particular tool or license is present.

No tool is bundled by this repository. IDA Pro, Hex-Rays, MCP bridges, and third-party utilities have their own licensing, installation, and compatibility requirements.

## Safety and scope

- Use the workflow only for software you own or are authorized to analyze.
- Treat unknown binaries and extracted artifacts as untrusted.
- Prefer static analysis first. Never execute an unknown sample on a personal or production host.
- If dynamic analysis is necessary, use an isolated, disposable, snapshotted, network-restricted lab.
- Do not treat anti-analysis observations as proof of maliciousness; report evidence and uncertainty.
- Do not use findings to compromise systems, steal data, evade detection in real deployments, or deploy malware.

See [`SECURITY.md`](SECURITY.md) for the project’s responsible-use guidance.

## Reporting principles

The workflow distinguishes:

- **Observed:** directly measured or present in the analyzed artifact.
- **Inferred:** the best explanation supported by current evidence.
- **Verified:** independently confirmed through a suitable cross-check.

Reports should include sample identity and hashes, tool versions where known, analysis scope, evidence, confidence, unresolved items, and the exact coverage achieved. “Fully unpacked,” “fully deobfuscated,” or “fully devirtualized” must not be claimed without evidence for that scope.

## Contributing

Corrections, examples, and workflow improvements are welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening an issue or pull request. Do not submit proprietary binaries, private data, credentials, or malware samples containing live secrets.

## License

This project is distributed under the MIT License. See [`LICENSE`](LICENSE).
