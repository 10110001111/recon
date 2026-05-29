# Network Reconnaissance Runbook

## Executive Summary

This runbook provides a comprehensive Nmap-based network reconnaissance procedure designed for internal security assessments. It walks through automatic subnet discovery via an RFC1918 sweep, scope validation, deep TCP and UDP service enumeration, OS and version fingerprinting, firewall behavior inference, NSE vulnerability scripting, and consolidation of all results into a single merged XML artifact for downstream parsing and reporting.

> **Third-party subnets are STRICTLY OUT OF SCOPE.** Networks belonging to airlines, government agencies, Interpol, partner organizations, service providers, or any external party must be explicitly excluded from every phase of this recon — discovery, scanning, and NSE scripting. Scanning third-party infrastructure without written authorization is illegal in most jurisdictions and can constitute a computer-misuse offense. Verify the live_ips.txt scope file against the approved engagement letter before proceeding to Section 3, and use `--exclude` or `--excludefile` on every Nmap invocation when any doubt exists.

> **Authorization required.** Confirm written scope before execution. The RFC1918 sweep is noisy and will trigger IDS alerts — coordinate with the blue team and asset owners before running.

---

## 1. Installation and Prerequisites

Nmap is pre-installed on most Debian-based distributions. The command below installs Nmap and masscan, and verifies the Nmap build. Both tools are required by this runbook.

```bash
# Refresh package lists, install nmap (port scanner) and masscan
# (fast host discovery sweep tool).
sudo apt update && sudo apt install -y nmap masscan && nmap --version
```

---

## 2. Automatic Subnet Discovery (RFC1918 Sweep)

The discovery phase actively sweeps the scoped target set (the RFC1918 ranges below are placeholders — replace them with your engagement subnets). A single full-port masscan pass (plus an ICMP echo probe) does double duty: it identifies every responsive host AND records every open TCP port in one sweep, so the same output feeds both the live-host list and the port list nmap uses in Section 3. A separate UDP masscan probe set catches UDP-only hosts. Responders from every sweep are unioned, sorted, and deduplicated into a single seed list. No separate Nmap host-discovery pass is run here — host discovery is deliberately skipped in Section 3 (via `-Pn`), so the unioned seed list is the authoritative target set. Because this pass is full-port, it is only practical against a bounded scope, not the entire private space.

### 2.1 Prepare Working Directory

```bash
# Create the recon working directory and enter it. All artifacts
# produced by this runbook will be written here.
mkdir -p ~/recon && cd ~/recon
```

### 2.2 Masscan + Nmap Sweep

```bash
# Phase 1a - masscan TCP + ICMP: full-port sweep of the target set plus ICMP
# echo on every host. Catches listeners and ping-responders in one pass.
# NOTE: full-port (-p0-65535) is only feasible against a BOUNDED target set.
# Replace the RFC1918 placeholders below with your scoped subnets first.
sudo masscan \
  -p0-65535 \
  --ping \
  10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 \
  --excludefile out_of_scope.txt \
  --rate 50000 --retries 1 --wait 5 \
  -oX masscan_sweep.xml

# Phase 1b - masscan UDP: catches SNMP/DNS/NetBIOS/IKE/IPMI/mDNS/NTP hosts
# that have no TCP services or ICMP exposed. Keep rate low; UDP responses
# are rate-limited by most stacks.
sudo masscan \
  -pU:53,67,123,137,161,500,623,1900,5353 \
  10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 \
  --excludefile out_of_scope.txt \
  --rate 10000 \
  --retries 1 \
  --wait 5 \
  -oX masscan_udp_sweep.xml

# Union responders from every XML, version-sort, dedupe. This is the
# canonical scope-validated target list for Section 3.
grep -hoP 'addr="\K[0-9.]+(?=")' *.xml | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -uV > seed_ips.txt
```

### 2.3 Extract Live IPs and Derived Subnets

```bash
# seed_ips.txt is the unioned live-IP list from the Phase 1 sweeps.
# Sort and dedupe into live_ips.txt as the scope-validated target list.
sort -uV seed_ips.txt > live_ips.txt

# Derive the parent /24 of every live IP. Useful for scope review
# (lets you see which subnets the sweep actually touched).
awk -F. '{print $1"."$2"."$3".0/24"}' live_ips.txt | sort -u > discovered_subnets.txt

# Print counts and the subnet list for the operator to eyeball.
wc -l live_ips.txt discovered_subnets.txt
cat discovered_subnets.txt
```

### 2.4 Manual Scope Review (Mandatory Checkpoint)

**STOP.** Before proceeding, open `discovered_subnets.txt` and `live_ips.txt`. Remove any out-of-scope subnets or IPs. Manually add any in-scope subnets that did not respond to the sweep (commonly due to ICMP/ARP filtering). The scan in Section 3 will operate against whatever remains in `live_ips.txt` — accuracy here is critical.

Build an `out_of_scope.txt` exclude file once and reference it on every Nmap and masscan invocation. Include all third-party ranges (airlines, government, Interpol, partners, ISP infrastructure, cloud-managed tenants) and any internal segments outside the engagement letter. One CIDR or IP per line, comments with `#`.

```bash
# Define the master exclusion list. Every nmap/masscan command in
# this runbook references this file via --excludefile (Nmap and masscan both use this spelling).
# One CIDR or IP per line. Comments allowed with #.
cat > out_of_scope.txt <<'EOF'
# Third-party / external networks - DO NOT SCAN
203.0.113.0/24      # Example airline partner
198.51.100.0/24     # Example .gov range
192.0.2.0/24        # Example Interpol-linked block

# Internal segments outside engagement scope
10.99.0.0/16        # Finance - out of scope per SOW
EOF
```

Remove out-of-scope IPs from the discovered live list (belt-and-suspenders alongside `--excludefile`):

```bash
# Drop any IP whose first two octets are 10.99 from live_ips.txt.
# Belt-and-suspenders alongside the --excludefile approach.
grep -v '^10\.99\.' live_ips.txt > tmp && mv tmp live_ips.txt
```

Manually add in-scope subnets that did not respond:

```bash
# Use nmap -sL (list scan, no packets sent) to enumerate every IP in
# a CIDR, then append them to live_ips.txt. For subnets you know are
# in scope but didn't respond to the sweep (e.g. ICMP/ARP blocked).
nmap -sL -n 192.168.250.0/24 | awk '/Nmap scan report/ {print $5}' >> live_ips.txt

# Re-sort and dedupe in place so the file stays clean.
sort -u live_ips.txt -o live_ips.txt

# Print final target count - last sanity check before Section 3.
echo "Final target count: $(wc -l < live_ips.txt)"
```

---

## 3. Comprehensive Recon Scan

This phase performs full TCP port enumeration, top-200 UDP enumeration, service and version detection, OS fingerprinting, traceroute, default and vulnerability NSE scripting, and firewall behavior inference. Outputs are written to separate XML files which are merged in Section 4.

### 3.1 TCP All-Port Scan

```bash
# Full TCP recon. Section 2.2 already full-ported the target set, so we
# reuse masscan_sweep.xml here - no second all-port scan. nmap deep-scans
# only the open ports: SYN scan + service/version + OS + safe NSE + traceroute.

# Collapse the open ports masscan already found into a comma-separated list
# so nmap probes only those ports, never all 65,535 again.
PORTS=$(grep -hoP 'portid="\K[0-9]+' masscan_sweep.xml | sort -un | paste -sd,)

# nmap deep scan on the discovered ports.
sudo nmap -sS -sV -O \
  --script "default,banner,firewalk,firewall-bypass,http-headers,\
http-title,ssl-cert,ssl-enum-ciphers,smb-os-discovery,\
smb-security-mode,snmp-info,ssh-auth-methods,ssh2-enum-algos" \
  -p "$PORTS" --open --reason --traceroute \
  -iL live_ips.txt --excludefile out_of_scope.txt \
  --min-rate 1000 --max-retries 2 --host-timeout 30m \
  -T4 -Pn -oX tcp_full.xml

# Flag-by-flag:
#   -sS                  SYN (half-open) scan - fast, low-footprint
#   -sV                  probe open ports to identify service + version
#   -O                   OS fingerprinting via TCP/IP stack quirks
#   -p "$PORTS"          scan only the ports masscan reported open
#   --script "..."       run extra NSE: banners, SSL/TLS
#                        cipher audit, SMB/SNMP/SSH enumeration,
#                        firewalk + firewall-bypass probes
#   --max-retries 2      cap probe retransmits (bounds time per port)
#   --open               only report ports that are open
#   --reason             show why nmap chose each state (firewall hint)
#   --traceroute         map hop-by-hop path to each host
#   -iL live_ips.txt     read target list from file
#   --excludefile ...    subtract out-of-scope ranges from targets
#   --min-rate 1000      send at least 1000 packets/sec (speed floor)
#   --host-timeout 30m   give up on any single host after 30 min
#   -T4                  aggressive timing template (LAN-safe)
#   -Pn                  skip host discovery (already done in Section 2)
#   -oX                  write XML output for downstream merge
```

### 3.2 UDP Top-200 Scan

```bash
# UDP recon: top 200 ports only (full UDP is impractical - tens of
# hours minimum due to ICMP rate-limiting). Captures DNS, SNMP, NTP,
# NetBIOS, IKE, IPMI, mDNS, etc.
sudo nmap -sU -sV --version-intensity 0 --top-ports 200 --open --reason \
  -iL live_ips.txt \
  --excludefile out_of_scope.txt \
  --min-rate 500 --max-retries 2 \
  --defeat-icmp-ratelimit --host-timeout 20m \
  -T4 -Pn \
  -oX udp_full.xml

# Flag-by-flag:
#   -sU                  UDP scan
#   -sV                  service-version probes on responsive ports
#   --top-ports 200      200 most common UDP ports by frequency
#   --open               hide closed/filtered noise
#   --reason             show classification reason per port
#   --min-rate 500       lower floor than TCP (UDP is rate-limited)
#   -T4 -Pn              aggressive timing, skip host discovery
#   -oX                  write XML output for downstream merge
```

### 3.3 Flag Reference

| Flag | Purpose |
|------|---------|
| `-sS` | TCP SYN (half-open) scan — fast and stealthy |
| `-sU` | UDP scan |
| `-sV` | Service and version detection |
| `-sC` | Run default NSE script category |
| `-O` | OS detection and version fingerprinting |
| `-p <list>` | Scan a specific port list (here, the open ports masscan found) |
| `--top-ports N` | Top N most common ports (UDP scan) |
| `--open` | Show only open (and open\|filtered) ports |
| `--reason` | Show why each port was classified — exposes firewall behavior |
| `--traceroute` | Map hop-by-hop path; reveals intermediate firewalls/routers |
| `-Pn` | Skip host discovery (already done in Section 2) |
| `-iL FILE` | Read target list from file |
| `-T4` | Aggressive timing — appropriate for internal networks |
| `--min-rate` | Floor on packets per second |
| `--min-parallelism` / `--max-parallelism` | Bound concurrent probes |
| `--script` | Run specific NSE scripts or categories |
| `-oX` | Output XML format (single canonical artifact) |

### 3.4 Firewall Up/Down Inference

Port states emitted with `--reason` directly indicate firewall behavior. Use the table below to interpret host posture without a separate scan.

| Observed State + Reason | Interpretation |
|--------------------------|----------------|
| `open / syn-ack` | Service listening; no filter in path |
| `closed / reset` | Host reachable, no service, no firewall (kernel RST) |
| `filtered / no-response` | Stateful firewall silently dropping packets |
| `filtered / admin-prohibited` | Router/firewall ACL actively rejecting |
| `open\|filtered (UDP)` | No response; cannot distinguish — typical UDP behavior |
| `unfiltered (ACK scan)` | Packet reaches host; state unknown — non-stateful filter |

The `firewalk` and `firewall-bypass` NSE scripts add explicit findings (allowed/denied probes per port) to the XML output, which the merge step preserves.

---

## 4. Merge into a Single XML Artifact

Nmap does not natively merge XML outputs. The Python snippet below merges each UDP `<host>` into the matching TCP `<host>` by IPv4 address (and appends any UDP-only hosts whole), producing one schema-valid XML file with a single host node per IP. The merged file is the canonical deliverable from this runbook. Note: ElementTree does not re-emit Nmap's XSL stylesheet reference, so the merged file is for data parsing, not for rendering with `nmap.xsl`.

```bash
# Merge tcp_full.xml + udp_full.xml into one nmaprun-rooted XML.
# Nmap has no built-in merge; this folds each UDP <host> into the
# matching TCP host by IP, so each IP appears once in the output.
python3 - <<'EOF'
import xml.etree.ElementTree as ET

tcp = ET.parse('tcp_full.xml').getroot()        # parent doc
udp = ET.parse('udp_full.xml').getroot()        # source of UDP results

# Index TCP hosts by IPv4 so UDP results merge into the SAME <host> node
# instead of producing a duplicate host per IP (one host per address).
def ip(h):
    a = h.find("address[@addrtype='ipv4']")
    return a.get('addr') if a is not None else None

tcp_by_ip = {ip(h): h for h in tcp.findall('host') if ip(h) is not None}

for uh in udp.findall('host'):
    th = tcp_by_ip.get(ip(uh))
    if th is None:                              # UDP-only host: add whole node
        tcp.append(uh)
        continue
    uports = uh.find('ports')
    if uports is None:
        continue
    tports = th.find('ports')
    if tports is None:                          # TCP host had no <ports> block
        th.append(uports)
    else:
        for p in uports.findall('port'):        # graft UDP <port> into TCP host
            tports.append(p)

# Update the args attribute to record both nmap invocations
tcp.set('args', tcp.get('args','') + ' || ' + udp.get('args',''))
ET.ElementTree(tcp).write('full_network_scan.xml',
                          xml_declaration=True, encoding='utf-8')
print('Wrote full_network_scan.xml')
EOF

# Confirm the merged artifact exists and check its size.
ls -lh full_network_scan.xml
```

---

## 5. Sanity Checks on the Merged Output

Run these one-liners against `full_network_scan.xml` to validate completeness and surface high-priority findings before deeper analysis.

```bash
# Count total host elements in the merged XML
# (one <host> per scanned IP that was up).
grep -c '<host ' full_network_scan.xml

# Pull every portid value, sort numerically, dedupe.
# Result: full list of unique open ports across the environment.
grep -oP 'portid="\K[0-9]+' full_network_scan.xml | sort -nu

# List IPs of hosts where an NSE script reported VULNERABLE. Only yields
# results if you ran a --script vuln pass (omitted from the default scan).
grep 'VULNERABLE' full_network_scan.xml | grep -oP 'addr="\K[0-9.]+(?=")' | sort -u

# Tally OS families detected by -O fingerprinting.
# Quick distribution view: how many Windows, Linux, IOS, etc.
grep -oP 'osclass.*osfamily="\K[^"]+' full_network_scan.xml \
  | sort | uniq -c | sort -rn
```

---

## 6. Operational Tips and Gotchas

- Run the entire workflow inside `tmux` or `screen`. Full-port TCP plus UDP scans across many hosts can take several hours; loss of an SSH session should not kill the scan.

- `-T4` is appropriate for stable internal networks. Drop to `-T2` for fragile OT/ICS segments or when noise must be minimized.

- Do not run `--script vuln` against production OT/SCADA, legacy printers, or embedded devices — some scripts can crash fragile stacks. Exclude those subnets with `--exclude` or scan them with `-sV` only.

- For deeper internal findings, follow up with credentialed NSE scans (SMB, SSH, SNMP, MSSQL, MySQL) using `--script-args` once initial scope is mapped.

- Always preserve raw XML outputs. Tools such as Metasploit's `db_import`, Eyewitness, and dnsx can ingest the merged file directly for downstream enrichment.

---

## 7. Deliverables Checklist

| File | Description |
|------|-------------|
| `masscan_sweep.xml` | Phase 1a masscan full-port sweep XML (live hosts + open-port map) |
| `masscan_udp_sweep.xml` | Phase 1b masscan UDP host-discovery XML |
| `live_ips.txt` | Final scope-validated target list |
| `discovered_subnets.txt` | Derived /24 subnets from live hosts |
| `out_of_scope.txt` | Master exclusion list (third-party + out-of-scope) |
| `tcp_full.xml` | TCP deep scan XML (service/version/OS/NSE on discovered ports) |
| `udp_full.xml` | UDP top-200 scan XML |
| `full_network_scan.xml` | Final merged XML — primary deliverable |
