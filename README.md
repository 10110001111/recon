# recon

A single-file, client-side visualizer for nmap XML output (`-oX`). Drop in a scan file and get an interactive breakdown of hosts, ports, services, NSE script results, and vulnerability findings — no server, no install, no data leaves your machine.

## Usage

Open `scan_visualizer.html` in any browser, then drop or browse to an nmap XML file:

```bash
nmap -sV -sC -O -oX scan.xml 192.168.1.0/24
```

For merged TCP + UDP scans, join them before loading:

```bash
nmap -sS -sV -p- -oX tcp.xml <target>
nmap -sU --top-ports 200 -oX udp.xml <target>
# merge with xsltproc or just load each separately
```

## Features

- **Stats bar** — total hosts, hosts up, open ports, unique services, vuln findings at a glance
- **Host cards** — expandable per-host view with IP, hostname, MAC, OS detection, port table
- **NSE script output** — all script results inline; vuln scripts highlighted and flagged
- **Vuln detection** — auto-flags hosts and ports where script output contains `VULNERABLE` or a CVE ID
- **Traceroute** — hop-by-hop path rendered per host when present in the XML
- **Filtering** — live search across IPs, ports, services, OS, script output; filter by protocol (TCP/UDP), service name, or vuln-only
- **Export** — copy live IPs to clipboard, export filtered results to CSV

## Notes

- Works entirely offline — no external requests except Google Fonts in the header
- Accepts any nmap `-oX` file; does not parse `.gnmap` or `.nmap` text formats
- Tested against nmap 7.9x output; should work with any modern nmap XML schema
