# Ironguard

Cross‑platform, AI‑assisted hardening tool for CyberPatriot competition images. Ships with a deterministic script mode (native Rust) and an AI mode (planning/execution once enabled).

## Important Disclaimer
- This tool makes invasive changes and can break systems, cause data loss, or violate competition rules if misused.
- Use at your own risk. By using Ironguard you agree that you assume all liability for its use.
- This tool may get you disqualified if it violates event rules. Confirm with your coach and the rulebook before use.
- The authors, contributors, and maintainer, are not responsible for any damages, losses, or penalties arising from the use of this software.

## One‑line Install

Linux (requires sudo):
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/scripts/install.sh)"
```

Windows (run from an elevated PowerShell):
```powershell
irm https://raw.githubusercontent.com/tanav-malhotra/ironguard/main/scripts/install.ps1 | iex
```

Installer behavior:
- Detects your OS/arch and downloads a prebuilt Ironguard binary from Releases
- Installs to PATH (Linux: /usr/local/bin; Windows: C:\\Program Files\\Ironguard) and verifies with `ironguard --help`

Note: Prebuilt binaries must be available at `https://github.com/tanav-malhotra/ironguard/releases`. Building during competition is discouraged to save time.

## Usage

1) Initialize configuration:
```bash
ironguard init
```
This creates a commented `ironguard.toml` tailored to your OS. Edit it and set at least:
- admins, users
- allowed_services, keep_packages
- optional force_remove (DANGEROUS: overrides allow/keep)
- [linux] knockd_enabled or [windows] allow_rdp

2) Dry‑run first (no changes):
```bash
ironguard run script --dry-run
```

3) Apply:
```bash
ironguard run script
```


Forensics solver (experimental)
Provider can be openai|anthropic|openrouter|ollama|gemini; model is provider-specific
Gemini example (requires GEMINI_API_KEY env or --api-key):
  $env:GEMINI_API_KEY="<key>"  # PowerShell
  export GEMINI_API_KEY="<key>" # bash
ironguard forensics --provider gemini --model gemini-2.5-pro --time-budget 3600 --allow-exec

AI mode (planning placeholder):
```bash
ironguard ai
```

## Philosophy
- Whitelist by default: keep only essential or explicitly allowed services/software
- Preserve critical services (time, network, firewall) and dependencies for kept software
- Provide DANGEROUS escape hatch `force_remove` for exceptional cases (use sparingly)

## Support
Issues and releases: `https://github.com/tanav-malhotra/ironguard`

## License
GPL‑3.0. See [LICENSE](https://github.com/tanav-malhotra/ironguard/blob/main/LICENSE).
