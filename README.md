# Scappy Network Probe

A small command-line utility for sending one TCP SYN or ICMP/ICMPv6 echo probe
to a specified IP address using Scapy.

## Responsible use

- Use this tool only on systems and networks you own or are explicitly
  authorized to test.
- This is a single-target probe tool, not a network scanner or a full
  traceroute implementation.
- The interactive menu and direct modes ask for confirmation before sending.
  `--yes` bypasses that confirmation; use it only when the target and action
  have already been checked.
- Run with the least privilege needed. Packet-sending permissions vary by
  operating system and network configuration; do not run as an administrator
  unless your environment requires it.
- The program logs response summaries. Avoid capturing or sharing output that
  contains information you are not authorized to disclose.

## Requirements

- Python 3
- Scapy (see [`requirements.txt`](requirements.txt))

Install the dependency in a virtual environment:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Usage

Start the interactive menu (default):

```powershell
python scappy.py 192.0.2.1
```

Choose a probe directly; confirmation is still required:

```powershell
python scappy.py 192.0.2.1 tcp
python scappy.py 192.0.2.1 icmp
```

To skip confirmation intentionally:

```powershell
python scappy.py 192.0.2.1 icmp --yes
```

IPv4 and IPv6 destinations are supported. The `traceroute` mode currently
sends a single ICMP/ICMPv6 probe; it does not trace intermediate hops.

## Tests

CI supports Python 3.11, 3.12, and 3.13.

Run the unit tests with:

```powershell
python -m unittest -v
```

Tests use mocks for packet transmission and do not intentionally send probes.
Packet-construction tests use Scapy locally.

GitHub Actions runs this suite on pushes to `main` and pull requests from
branches in this repository. Fork pull requests create a workflow run, but
the test job is skipped. The workflow has read-only repository permissions,
and packet-send tests use mocks.

## Dependency updates

Dependabot checks Python dependencies and GitHub Actions weekly and opens
update pull requests for review. Review dependency changes before merging; no
automatic merging is enabled.

## License

No license file is included. Confirm the applicable license with the project
owner before redistributing or reusing this code.
