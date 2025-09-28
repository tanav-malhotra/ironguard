# Ironguard Project Plan

## Vision
- Deliver a cross-platform, AI-assisted hardening tool that can autonomously secure CyberPatriot competition images fast and thoroughly, maximizing score across Windows desktop, Windows Server, and Debian/Ubuntu/Mint variants.
- Present a Codex-like chat/TUI so teammates can interact via natural language and slash commands while the agent performs the bulk of remediation.

## High-Level Requirements
- Support Windows 10/11, Windows Server 2016/2019/2022, and Debian/Ubuntu/Mint (extensible to more distros like Fedora).
- Provide two execution tracks: `/run script` (deterministic offline hardening driven by Rust modules + `ironguard.toml`) and `/run ai` (adds LLM-driven decisions using README and host data).
- Default to GPT-5 for OpenAI and Gemini 2.5 Pro for Google; bundle a provider registry that also exposes GPT-5-Codex (code-first GPT-5 variant), Grok-4, and future drop-ins via config; allow `/model` swap, with an `--offline` flag that disables all network/LLM usage while still hardening.
- Auto-discover the competition README HTML on the current user's Desktop; README directives always override config defaults.
- `ironguard.toml` in the working directory defines required admins/users/groups, allowed services, forbidden software, network policy (SSH port default 22 with a comment recommending change unless README insists), scoring check cadence, and other knobs.
- AI agent can read/write files, list directories, run commands, inspect score report HTML, and log rationale; must cross-check README hints (themes, character names, etc.) for hidden vulnerabilities; dynamic provider selection should inject the right safety/compliance prompts per vendor, enforce dry-run when not elevated (with prominent warnings), and persist conversation state so `/continue` resumes after interruptions.
- TUI mirrors Codex CLI ergonomics: single-pane chat with history, autocompletion, slash command hints, status footer, Shift+Enter for multiline, `--yes`/`--no-confirm` to skip confirmations, `/pause` to halt automation, `/status` for progress, `/log` toggle, `/config` to inspect current settings.
- Logging is opt-in via `--log` or `/log on`; when enabled, write detailed (up to ~1000 lines) JSON logs under `%USERPROFILE%/.ironguard/<timestamp>/` (future Markdown/HTML variants with CSS styling).
- Never run the hardening routines on the developer's personal machine; local work limited to `cargo check`, `cargo build`, `cargo doc`, etc.
- Package as static binaries per target OS (Rust preferred; C++ only if a module truly needs it, with static linkage).
- Provide GPLv3 licensing artifacts, README, user docs (post MVP), and keep room for future modules (e.g., scoring engine reverse engineering).

## Project Plan
1. Repository Baseline & Planning
   - Maintain this PROJECT_PLAN.md as the single source of truth for instructions, decisions, and status.
   - Inventory existing bash/ps1 scripts (linux/windows/server) to capture required hardening behaviors.
2. Core Architecture Design
   - Define Rust crate layout (CLI entrypoint, TUI UI layer, automation engine, AI integration, platform modules, logging/config utilities).
   - Establish command execution abstraction that can fall back from native APIs to shell/PowerShell when needed.
3. Configuration & Data Modeling
   - Specify `ironguard.toml` schema, defaults, and validation rules (users/admins/groups/services/ports/software/firewall/password policies/scoring checks).
   - Model README directive extraction (HTML parsing -> structured policy + free-form context for AI).
4. Offline Automation Engine
   - Re-implement existing bash/PowerShell logic as idempotent Rust modules for Linux and Windows (accounts, services, package hygiene, firewall, auditing, PAM/GPO tweaks, malware scans, container checks, etc.).
   - Ensure multi-path remediation (apply all known scoring variants) and full parity with reference scripts plus gaps identified from competition outcomes.
5. AI Assistant Layer
- Integrate GPT-5/Gemini through pluggable providers, manage API keys via env/config prompts, support `/model`, offline fallback, rate limiting, and guardrail prompt templates tailored per provider.
   - Implement decision flow: README + config + host state -> plan -> preview -> execute (respecting `--yes`/confirm toggles and `/pause`).
6. TUI & UX Implementation
   - Build Codex/Claude Code-style interface (prompt line, autocompletion, history, slash command palette, status footer, streaming output, command previews, action diffs, tasteful animations/spinners).
- Provide `/run script`, `/run ai`, `/readme [path]`, `/status`, `/users`, `/services`, `/config`, `/log`, `/model`, `/help`, `/continue`, `/quit`.
7. Logging, Reporting, and Score Tracking
   - Implement optional JSON logging with action timeline, AI rationale, remediation diffs, and resource links; placeholders for Markdown/HTML exporters.
   - Add score report polling (read HTML on Desktop) with configurable cadence and TUI notifications.
8. Cross-Platform Build & QA
   - Set up CI/build scripts for Windows (MSVC), Linux (GNU/Musl), ensure static linkage, and run automated tests/lints.
   - Regression-test offline modules in VMs; prepare instructions for semi-automated validation (since we cannot run real hardening on dev machine).
9. Documentation & Release Prep (post-MVP)
   - Draft README, quickstart, teammate guide, cargo docs, and release notes; plan GitHub releases with per-OS binaries.
   - Capture lessons-learned for future scoring-engine reverse engineering project.

## Outstanding Tasks
- Finalize `ironguard.toml` key list (users/admins/groups/services/software/firewall/ports/password policies/score check interval/etc.).
- Document detailed behavior expectations from existing scripts (Linux + Windows + Server) to guarantee feature parity and identify missing remediation steps (e.g., multifaceted service disabling, PAM/GPO hardening, malware scans, container security, password enforcement, fail2ban, etc.).
- Design the command preview/confirmation UX for non-`--yes` runs.
- Decide on HTML parsing crate and AI prompt templates for README + host state fusion.
- Choose Windows remediation approach order (native Win32 APIs first, fallback to PowerShell/wmic/net commands) and create abstraction layer.
- Map out scoring-report polling logic (path detection, parse frequency, TUI alerts).
- Define logging JSON schema (action id, timestamp, command, result, AI rationale, resource links).
- Plan for API key management strategy (env var names, config prompts, secure storage expectations for teammates).
- Outline strategy for multi-path remediation on Linux to cover scoring edge cases (apply both `ufw` and `iptables`, etc.).

## Ongoing Instructions
- Keep this PROJECT_PLAN.md up to date every work session; treat it as the memory source if anything is forgotten.
- Maintain a concise conversation summary here when major decisions are made (see Conversation Log).
- Always follow README directives over config defaults; ensure automation honors that precedence.
- Prioritize thorough remediation over raw speed, but optimize execution time wherever possible.
- Default SSH port to 22 unless README/config specifies otherwise; include comment nudging users to customize.
- Ensure AI checks score report HTML periodically during `/run ai` and reports deltas.
- Favor Rust implementations; only introduce C++ if absolutely required and statically link everything.
- Never execute the hardening routines on the development machine; restrict local commands to safe build/documentation tasks.
- Plan for future modules (e.g., scoring-engine reverse engineering) but keep scope focused on current MVP.
- Default LLM providers: GPT-5 (OpenAI) and Gemini 2.5 Pro; allow offline mode fallback without AI.

## Current Status Notes
- 2025-09-20: Initial planning session with Tanav; requirements captured, existing scripts inventoried, architecture outline drafted. AI must exceed prior bash/ps1 coverage and support fully autonomous runs with optional confirmations.
- 2025-09-27: Added experimental `forensics` subcommand with MVP workflow skeleton, time budget, minimal TUI, desktop discovery, question scan, score report open, and placeholders for AI execution and penalty handling. Next: provider adapters, real tool-use, richer TUI (Claude Code CLI aesthetic), and scoring engine probes.

## Reference: Existing Script Coverage Snapshot
- `linux/debian.sh` handles package updates, repository management, removal of prohibited software (telnet/nginx/etc.), multiple malware scanners (chkrootkit, rkhunter, clamav), account auditing, SSH hardening (port changes, Protocol 2, auth options), PAM password policies, firewall setup (ufw/iptables), fail2ban, service auditing, container security checks, media/script finders, user-password resets, forensics prompts, and reboot prompts.
- Supporting Linux scripts (`anomaly_scan.sh`, `malware_scan.sh`, `recent_files.sh`, `script_finder.sh`, etc.) perform targeted searches for anomalies, suspicious files, base64 blobs, peripheral hardening, and display configuration.
- Windows scripts rename Administrator accounts, enforce password/lockout policies, manage services/features, remove prohibited software/games, configure firewall/GPO settings, enable auditing/logging, and prompt for forensic question completion.
- Server PowerShell script extends Windows logic to server roles, service baseline checks, and update management.
- All reference scripts log actions verbosely, assume interactive confirmations, and rely on shell utilities; new Rust engine must replicate these behaviors programmatically and support simultaneous methods when scoring ambiguity exists.

## Conversation Log
- 2025-09-20: Kickoff conversation captured project goals, OS targets, AI expectations, logging approach, README precedence, slash command set, and requirement to maintain this plan file.

