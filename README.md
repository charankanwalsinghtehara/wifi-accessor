# CyberSentinel AI

CyberSentinel AI is a native Linux Streamlit application for authorized, defensive Wi-Fi
configuration assessments. It uses Linux-provided wireless metadata and a LangGraph workflow;
it does not require Docker, root privileges for ordinary discovery, or monitor-mode hardware.

## Features

- Enumerates wireless adapters and reports the Linux distribution and available networking tools.
- Discovers nearby SSID/BSSID, channel, frequency, signal strength, and advertised security using
  NetworkManager (`nmcli`) or `iw`.
- Uses `iwconfig` only as a legacy interface-enumeration fallback; it does not pretend that
  `iwconfig` can discover nearby networks.
- Identifies open, WEP, WPA, WPA/WPA2, WPA2, WPA3, and WPA2/WPA3 transition-mode advertisements.
- Reviews WPS information only when exposed by scan metadata. It never sends WPS
  probes or attempts PIN registration.
- Audits an owner-supplied Wi-Fi passphrase locally and clears the UI input after the audit.
- Lists NetworkManager profiles restricted to the logged-in user or configured as system-wide.
  Profiles restricted to other users are excluded. An explicitly confirmed request asks
  NetworkManager for the selected key, subject to native OS permissions. Running the application
  as root is refused for recovery. No privilege escalation or permission bypass is attempted.
- Maintains assessment history in SQLite and creates timestamped JSON and HTML reports.
- Coordinates authorization, scope validation, discovery, analysis, and reporting through
  LangGraph. All subprocesses pass through a strict `nmcli`/`iw`/`iwconfig` allowlist; no model can
  execute shell commands.
- Optionally produces sanitized commentary with a local Ollama model or OpenAI. Passphrases are
  never sent to either provider; the LLM receives only finding titles and severity labels.

## Linux setup

Install Python 3.10+ and the Wi-Fi tools supported by your distribution. For example, on Debian
or Ubuntu:

```bash
sudo apt install network-manager iw wireless-tools
```

`nmcli` is preferred. `iw` is used when NetworkManager is unavailable. Some drivers restrict `iw`
scans to privileged users; the application reports permission failures and never invokes `sudo`.
Ordinary adapter enumeration and NetworkManager discovery should be run as the normal logged-in
desktop user.

```bash
cd cybersentinel-ai
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
streamlit run app.py
```

The application runs directly on Linux. No container runtime is used.

## Authorization and safety

- Every assessment action requires the explicit authorization checkbox in the Wi-Fi page.
- Each Wi-Fi operation validates an exact target scope (selected interface, SSID, or user-owned
  connection UUID). Invalid authorization or scope is blocked before the graph can execute tools.
- Discovery is limited to wireless metadata on the selected local interface. The application does
  not scan arbitrary IP ranges, capture packets, perform password guessing, test authentication,
  or alter adapter settings.
- Security findings describe observed metadata. They do not claim that a passphrase or access
  point setting was verified when it cannot be observed from the beacon.
- Password audits are local-only. Plaintext passphrases are not written to logs, reports, or
  assessment history.
- Saved-key retrieval uses the current user's NetworkManager profile and native permission checks.
  The key is displayed only for that request and is not placed in history or a report.
- `logs/audit.log` contains structured assessment actions with secret-field redaction.
- Website and infrastructure pages remain offline references/simulations; they do not scan hosts.

## Optional LLM commentary

LLM commentary is disabled by default. To use Ollama locally, set `LLM_PROVIDER=ollama`,
`LLM_MODEL` to an installed model, and optionally `OLLAMA_BASE_URL` (the host must be local).
For OpenAI, set `LLM_PROVIDER=openai`, `LLM_MODEL`, and `OPENAI_API_KEY` in the environment or
`.env`. The OpenAI request includes only finding titles and severities. Deterministic local checks
remain authoritative; the model has no tools and cannot execute commands.

## Tests

Tests use mocked command output and do not require a wireless adapter:

```bash
python -m pytest -q
```

Coverage includes nmcli/iw parsing, WPA classification, authorization and scope enforcement,
command allowlisting, secret redaction, password auditing, LangGraph routing, report generation,
and error handling.

## Project layout

- `agents/` — orchestrator and Wi-Fi discovery, security, password, recovery, reporting, and
  optional LLM agents
- `networking/linux_wifi.py` — Linux distribution, utility, wireless-interface, and network
  metadata abstraction
- `security/` — authorization, scope validation, allowlisted command execution, and audit logging
- `workflows/assessment_graph.py` — LangGraph assessment workflow
- `pages/` — Streamlit interface
- `database/` — SQLite assessment history
- `tests/` — automated mocked and policy tests
