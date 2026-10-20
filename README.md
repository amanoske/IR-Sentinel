# Sentinel

Sentinel is a local Python MCP service and Codex plugin for incident response.
Set it up once, supply evidence in Codex, and ask for an investigation.

It investigates PCAP/PCAPNG traffic, files and malware hashes; correlates observed
indicators with AlienVault/LevelBlue OTX; and creates defensive rule candidates and
response guidance. Python and local engines perform the analysis. Codex coordinates
typed tools. No model API key, Daybreak feature, or additional MCP server/plugin is
required.

## Contents

- [Install](#install)
  - [Prerequisites](#prerequisites)
  - [Set up once](#set-up-once)
  - [Optional OTX key](#optional-otx-key)
- [Investigate](#investigate)
  - [Traffic](#traffic)
  - [Files and hashes](#files-and-hashes)
  - [Threat intelligence](#threat-intelligence)
  - [Defensive rules and response](#defensive-rules-and-response)
- [Examples](#examples)
- [Update and uninstall](#update-and-uninstall)
- [Troubleshooting](#troubleshooting)
- [Data and limitations](#data-and-limitations)
- [Development](#development)

## Install

### Prerequisites

- **Linux or macOS**, Python **3.11+**, and Git. Linux is exercised by CI and the
  native-engine tests. macOS support uses the same POSIX implementation but is not
  currently covered by CI. Native Windows is not supported in this release.
- **Codex CLI**, signed in, with the `codex plugin` commands available. Follow the
  [official Codex CLI setup](https://developers.openai.com/codex/cli/).
  Desktop users also install the CLI for the one-time plugin registration, using
  the same OS account and Codex configuration as the Desktop app.
- For Desktop, an installed Codex app that supports **local plugins and execution**.
  Use a local chat so the service can read your supplied file.
- Internet access during installation to download Python dependencies. OTX is the
  only runtime network integration, and local investigation does not require it.

Check the prerequisites:

```sh
python3 --version
codex plugin --help
codex login
```

On Ubuntu 24.04+, Python and Git can be installed with:

```sh
sudo apt-get update
sudo apt-get install python3 python3-venv git
```

On Fedora:

```sh
sudo dnf install python3 python3-pip git
```

**Native analysis tools are optional and detected automatically:**

- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) extracts packet
  records, IPs, DNS queries, TLS names and HTTP request fields.
- [Suricata](https://docs.suricata.io/en/latest/install.html) collects offline
  protocol metadata and validates/replays generated rules.
- [Zeek/Bro](https://docs.zeek.org/en/current/install.html) collects offline
  connection/protocol logs and validates/replays generated scripts.

Install those you want using their official instructions. Sentinel reports missing
tools and continues with available capabilities. Full packet findings and HTTP rule
generation need TShark. File/hash analysis needs none of these tools. Sentinel does
not install privileged system packages or require live-capture permissions.

### Set up once

```sh
git clone https://github.com/amanoske/IR-Sentinel.git
cd IR-Sentinel
python3 manage.py install
```

That command installs the Python service in a managed virtual environment, packages
the plugin with its absolute interpreter path, and registers it with Codex. Codex
starts and stops the MCP process as needed. There is no separate server to run, no
virtual environment to activate, and no configuration/output folder to choose.

Start a **new local chat** in Codex CLI or Desktop. Ask:

> Use Sentinel to check that it is ready.

For a terminal check:

```sh
python3 manage.py doctor
```

The same installed plugin serves CLI and Desktop. It is registered as
`sentinel@ir-sentinel`, keeping its marketplace distinct from other plugins.
If Desktop was already open, restart it to refresh the installed plugin list.
The package uses the [supported Codex plugin format](https://developers.openai.com/plugins/build/plugins).

### Optional OTX key

Obtain your API key from your [OTX account](https://otx.alienvault.com/), then run:

```sh
python3 manage.py otx
```

Enter the key at the hidden terminal prompt. Do not paste it into Codex chat or put
it in a shell command. Sentinel stores it in a private user configuration file.
You do not need to export environment variables or repeat this step each session.
Saving a key does not send evidence anywhere; only an explicit intelligence lookup
sends selected IOC values to OTX. Local investigations work without a key.

Use the same command to replace the key. To remove it:

```sh
python3 manage.py otx --remove
```

## Investigate

Supply your evidence directly in Codex and ask for the investigation. Sentinel
reads the supplied file **in place**; it does not copy or relocate it. If a client
does not expose an attachment as a local file, provide its existing local path.
You never need to put evidence in a Sentinel-specific folder.

### Traffic

> Use Sentinel to investigate this capture. Explain suspicious activity, cite the
> packets behind each finding, and give me the limitations and next response steps.

The service identifies captures by their file header, runs available local engines
offline, and returns a case ID, referenced observations and a local report link.
Suspicious request syntax is an observation of a possible attempt, not proof of
successful exploitation. Encrypted traffic and missing engines limit visibility.

### Files and hashes

> Use Sentinel to investigate this file without executing it.

Sentinel computes MD5/SHA-1/SHA-256, records size and a basic format hint, and extracts
a bounded sample of printable strings with byte offsets. This is static triage,
not a malware sandbox or a complete antivirus scanner. It does not execute files,
expand archives, extract attachments or upload samples.

You can also supply an MD5, SHA-1 or SHA-256 string directly:

> Investigate this SHA-256 with Sentinel and check its OTX associations: …

A supplied hash alone cannot establish what happened on an endpoint.

### Threat intelligence

> Correlate this case's public indicators with OTX. Compare the reporting dates
> with the captured activity and explain possible associations without overstating attribution.

OTX queries use its [documented indicator API](https://github.com/AlienVault-OTX/OTX-Python-SDK).
Results retain the request URL, retrieval time, observed evidence references, Pulse
summaries and reported adversary labels. Up to ten selected indicators are queried
per call. Private/reserved IPs and recognized internal domains are withheld.
Organization-confidential domains and hashes should also be excluded from selection.

An OTX association is a **provider claim**, not an actor identification. Sentinel
compares Pulse publication dates to packet observation times, flags later reporting,
and keeps attribution unknown. Publication dates are not malicious activity dates.
A missing match, rejected key, timeout or rate limit is inconclusive. File timestamps
are not treated as incident timestamps.

### Defensive rules and response

> Generate a Suricata rule for the suspicious HTTP request. Validate it against this
> capture and the benign comparison I supplied. Explain what it covers.

Suricata and Zeek candidates currently match a suspicious HTTP URI observed in the
case. The generated artifact includes its evidence references and content hash.
Sentinel runs native syntax checks and offline replay. Sample-level validation
requires a positive match on the case capture and no matches on the supplied benign
capture. Without a benign comparison, false positives remain untested.

File/hash cases can produce a JSON hash watchlist for review. Rule generation for
other traffic behaviors is not yet implemented; unsupported requests are reported.

Reports propose evidence preservation, endpoint corroboration and response review.
Sentinel does not deploy rules, isolate hosts, block addresses or restart services.
Review scope and false positives before applying any defensive action yourself.

Before and after analysis/replay, Sentinel verifies the source hash. If the file
changed or disappeared, supply it again for a new investigation. No retained copy
is created to work around missing evidence.

## Examples

The [`example/`](example/) folder includes a harmless file and a standard-library
script that creates synthetic suspicious and benign HTTP captures:

```sh
python3 example/generate.py
```

Supply `example/traversal.pcap` to Codex. For a benign comparison, supply
`example/benign.pcap`. The script sends no traffic and includes no exploit payload
or real malware. The suspicious request receives a synthetic 403 response; the
expected conclusion is a possible traversal attempt, not successful compromise.

## Update and uninstall

Update from this checkout:

```sh
git pull
python3 manage.py install
```

Restart your local Codex chat after updating. Your OTX key and generated reports
remain available.

Remove the plugin, managed runtime and saved OTX key:

```sh
python3 manage.py uninstall
```

Also remove generated case reports and analysis output:

```sh
python3 manage.py uninstall --purge
```

Your original evidence is never deleted. The source checkout remains yours to keep
or remove. No other plugins or system analysis tools are removed.

## Troubleshooting

- **`codex plugin` unavailable:** update Codex CLI and retry installation.
- **Plugin absent in Desktop:** use the same OS account/configuration as CLI,
  restart Desktop, and open a local chat. Check `codex plugin list`.
- **Missing engine:** install the named tool and rerun `python3 manage.py doctor`.
  Discovery checks PATH and common Unix installation paths, including `/opt/zeek/bin`.
- **Attachment inaccessible:** supply the existing local path from the computer
  running Codex. Cloud-only attachment references are not local filesystem paths.
- **File changed/missing:** supply the evidence again; Sentinel deliberately stores
  no evidence copy. Keep source files available while replaying rules.
- **OTX rejected/rate limited:** replace the key with `python3 manage.py otx`, or wait
  before retrying a rate-limited request. Local analysis continues to work.
- **Permission error:** run setup as your normal user. Sentinel's managed directories
  must be user-owned and private; never run the service as root.

## Data and limitations

Normal use needs no path configuration. Defaults on supported Unix systems are:

- `~/.local/share/ir-sentinel`: installed runtime and plugin.
- `~/.config/ir-sentinel`: private OTX credential file (mode 600).
- `~/.local/state/ir-sentinel`: generated case records, reports, native-engine logs
  and rule candidates, under private directories (mode 700).

Existing XDG directory preferences are respected. Generated records include source
paths, hashes, selected strings/packet fields and provider results; these may be
sensitive even though the original file is not copied. Uninstall with `--purge`
removes those generated records. There is no telemetry or background enrichment.

Inputs are limited to 128 MiB; TShark examines at most 10,000 packets. Native engine
runs are time/output bounded. Indicator, string and log extraction limits are
reported. This first release has narrow heuristics and does not claim comprehensive
malware detection, full protocol coverage, forensic acquisition, or attribution.
Keep your local parsing tools patched when examining untrusted files.
