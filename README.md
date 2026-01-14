# netsec-baseline-recon
A small, defensive network reconnaissance tool for establishing a security baseline on local networks.

## Overview

`netsec-baseline-recon` helps you understand what is happening on a network before you decide to trust it.

It was built to provide a fast and structured view of network exposure, focusing on visibility, exposed services, and basic risk signals. The tool does not attempt exploitation and does not perform intrusive actions. Its purpose is awareness and informed decision-making, not attack.

The guiding question behind the project is simple:

> Is this network safe enough for me to operate on?

## Background and motivation

This project started as a practical solution to a common problem.

When traveling or working remotely, it is often necessary to connect to WiFi networks that are shared or only partially trusted. Hotels, short term rentals, coworking spaces, and guest networks frequently lack proper isolation or expose management services without users being aware of it.

In those situations, most people connect blindly.

`netsec-baseline-recon` was created to give quick, understandable answers such as:

* Are other devices visible on the network?
* Is the gateway exposing administrative or management services?
* Does the network appear to enforce client isolation?
* Are there vulnerability indicators that suggest additional caution?

The goal is not to prove a network is secure, but to highlight when extra care, a VPN, or avoidance is justified.

## What the tool does

At its core, the tool performs a baseline reconnaissance pass on either a local network or a single target host.

It automatically detects the active WiFi subnet and gateway, discovers reachable devices, and enriches results with hostnames and vendor information when available. 

The gateway or selected target is then analyzed for exposed TCP services and basic vulnerability indicators using non-intrusive Nmap scripts.

If CVE identifiers are referenced, they are classified using the official NVD API to provide severity context. The final output is a structured summary that highlights visibility, exposure, and risk in a way that is easy to interpret.

Reports are sent via Telegram, which allows the tool to be used on headless systems or small devices without relying on local output files.

## Usage

The tool supports two operating modes.

### Network mode (default)

When executed without arguments, the tool scans the local WiFi subnet and analyzes the WiFi gateway.

This mode is intended for unknown or shared networks.

```bash
./netsec-recon.sh
```

### Host mode

When an IPv4 address is provided, subnet discovery is skipped and the analysis focuses on the specified host.

```bash
./netsec-recon.sh 192.168.1.42
```

This is useful for self-assessment, lab environments, or controlled testing.

## Output

The report is divided into clear sections that reflect how a security engineer would reason about a network:

* Network context and scan scope
* Visibility of other devices
* Target identification
* Exposed services with contextual risk notes
* Vulnerability indicators and CVE severity
* A summarized risk assessment with recommended actions

The language is intentionally descriptive rather than alarmist.

## Design and implementation notes

All scanning is executed inside a Docker container running Nmap. This keeps the host environment clean and ensures consistent behavior across systems.

The container configuration follows a defensive approach: minimal privileges, read-only filesystem, and no persistence. The tool does not require direct installation of Nmap or related dependencies on the host.

From a security perspective, the project deliberately limits itself to reconnaissance and signal gathering. There is no exploitation logic, no brute forcing, and no credential handling. This makes the tool suitable for learning, defensive assessment, and authorized environments.

## Intended audience

This project is aimed at people who want to better understand real network exposure, including:

* Security engineers and analysts
* Cloud and infrastructure engineers
* Students learning network security concepts
* Remote workers and travelers operating on untrusted networks

As a portfolio project, it demonstrates practical skills in Bash scripting, Docker security, network analysis, API integration, and structured reporting.

## Legal and ethical considerations

Only run this tool on networks you own or are explicitly authorized to assess.

Always respect local laws, organizational policies, and terms of service.

## Project structure

```text
netsec-baseline-recon/
├── netsec-recon.sh      # Main orchestration script
├── lib/
│   └── core.sh          # Core logic and helper functions
├── nvd_classify.py      # CVE classification using the NVD API
├── docker-compose.yml   # Hardened Nmap execution environment
├── .env.example         # Environment variable template
└── README.md
```

## Configuration

Sensitive configuration is provided via a `.env` file:

```env
TELEGRAM_BOT_TOKEN="YOUR_TELEGRAM_TOKEN"
TELEGRAM_CHAT_ID="YOUR_TELEGRAM_CHAT_ID"
NVD_API_KEY="YOUR_NVD_API_KEY"
```

Secrets are never hardcoded and are excluded from version control.

## Project status

This repository represents a stable baseline version of the tool.

The design prioritizes clarity, safety, and signal quality over feature density. Future improvements may focus on usability or additional enrichment, but the defensive scope of the project will remain unchanged.

## License

This project is licensed under the MIT License.

You are free to use, modify, and distribute this software, provided that the original copyright
notice and license text are included.

## Author

Oswaldo Reátegui García  
Cloud Security and Digital Operations Engineer