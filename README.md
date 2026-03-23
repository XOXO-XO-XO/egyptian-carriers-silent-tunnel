# Operation iPRACEVPN
### Technical Incident Report — Foreign Surveillance Infrastructure on Egyptian Carrier Networks

**Investigator:** Amir Elbelawy — Computer & Communications Engineering, Mansoura University  
**Date:** March 17–18, 2026  
**Classification:** Public Disclosure  
**Tools:** Android (Termux), Kali Linux, free public APIs only  
**Reported to:** EG-CERT (incident@egcert.eg), NTRA

---

## TL;DR

A free-internet configuration file circulating on Egyptian social media (Telegram, WhatsApp) was traced to a foreign-operated VPN infrastructure running undetected on e&, Vodafone, and WE Telecom networks since December 2022. The operation routes Egyptian user traffic through foreign servers across 20+ countries, collects device hardware IDs (HWIDs), and is operated from infrastructure linked to Chinese-origin tooling, Moldovan bulletproof hosting, and a Moscow-based server hosting Chinese business domains. Formal disclosure was submitted to EG-CERT and NTRA on March 17, 2026.

---

## Discovery

A `.hc` configuration file named `مجاني لخط اتصالات` ("Free for a communications line") was shared via a Telegram channel (Telegram (channel name withheld — provided to authorities)) and Egyptian WhatsApp groups promising free internet access on Egyptian carriers.

Initial examination: the `.hc` extension is associated with VeraCrypt encrypted containers. File contents appeared as binary/encrypted data. Standard file analysis returned no readable content.

**First finding:** the file was not a VeraCrypt container. It was an HTTP Custom app configuration file — an encrypted tunnel config for routing mobile data through SSH-over-SSL.

---

## Phase 1 — App Analysis

Loaded the `.hc` file into the HTTP Custom Android app. Connection log revealed:

```
Carrier: e& Egypt (اتصالات مصر) — LTE 4G
Protocol: SSL/TLS with SNI → SSH tunnel
SSH Server: Dropbear 2020.81
SSH Fingerprint: 9e:bc:6b:aa:4d:48:f5:d1:54:c6:f0:4e:7c:2b:ff:39
Key Exchange: diffie-hellman-group14-sha1
Encryption: aes256-ctr + hmac-sha2-256
Auth: password
DNS: 8.8.8.8 / 8.8.4.4
```

App settings showed:
- SSL only (no payload, no SlowDNS, no V2ray)
- HWID collection confirmed: `[REDACTED]`
- Config locked by creator — credentials not visible to user
- Creator promotion: Telegram channel and WhatsApp channel (identifiers withheld — provided to EG-CERT and NTRA)

**The mechanism:** the app uses SNI spoofing — presenting a zero-rated domain in the TLS handshake to bypass carrier billing, while the actual traffic routes to a foreign SSH server. The carrier sees a whitelisted domain and does not bill the data. All user traffic is tunneled through the operator's server.

---

## Phase 2 — Exit Node Identification

Verified tunnel was active, then checked exit IP:

```bash
curl -s https://ipinfo.io/json
```

```json
{
  "ip": "57.131.38.151",
  "hostname": "vps-1dc66b84.vps.ovh.net",
  "city": "Milan",
  "region": "Lombardy",
  "country": "IT",
  "org": "AS16276 OVH SAS"
}
```

**Finding:** all Egyptian user traffic was exiting through an OVH VPS in Milan, Italy. The operator is OVH SAS (AS16276), a major European hosting provider.

---

## Phase 3 — Port Scan

Full TCP port scan of the primary server:

```bash
nmap -sV -p 1-65535 57.131.38.151
```

**Results (selected open ports):**

```
PORT      STATE  SERVICE        VERSION
22/tcp    open   ssh?
80/tcp    open   http           Golang net/http server
88/tcp    open   kerberos-sec?
110/tcp   open   pop3?
143/tcp   open   imap?
440/tcp   open   sgcp?
441/tcp   open   decvms-sysmgt?
442/tcp   open   cvc_hostd?
443/tcp   open   ssl/https?
444/tcp   open   snpp?
446/tcp   open   ddm-rdb?
447/tcp   open   ddm-dfm?
1723/tcp  open   tcpwrapped     (PPTP VPN)
2082/tcp  open   http           Golang net/http server
2083/tcp  open   radsec?
2095/tcp  open   nbx-ser?
2096/tcp  open   http           Golang net/http server
8443/tcp  open   https-alt?
64831/tcp open   unknown
```

**Analysis:**
- Ports 80, 2082, 2096: **Golang net/http server** — custom management panel
- Ports 440–447: SSH cluster around 443 — designed to appear as HTTPS traffic to carrier inspection
- Port 2095: hung on connection (no response) — likely HWID verification endpoint
- Ports 2082/2083/2095/2096: Cloudflare-compatible port set, consistent with panels designed to operate behind CDN
- Port 1723: PPTP VPN — multiple protocol support confirmed

---

## Phase 4 — Infrastructure Mapping

### Primary domain enumeration:

```bash
curl -s "https://api.hackertarget.com/hostsearch/?q=ipracevpn.com"
```

Returned **48 subdomains** across 15+ countries:

```
au-ssh.ipracevpn.com     → 170.64.161.189  (Australia)
br-ssh.ipracevpn.com     → 95.164.4.51     (Brazil)
ca-ssh.ipracevpn.com     → 158.69.208.120  (Canada)
de-ssh.ipracevpn.com     → 57.129.121.229  (Germany)
de2-ssh.ipracevpn.com    → 167.172.109.92  (Germany 2)
es-ssh.ipracevpn.com     → 159.89.6.233    (Spain)
fr-ssh.ipracevpn.com     → 137.74.119.72   (France)
hk-ssh.ipracevpn.com     → 74.119.193.61   (Hong Kong)
id-ssh.ipracevpn.com     → 172.232.250.166 (Indonesia)
in-ssh.ipracevpn.com     → 159.65.159.181  (India)
it-ssh.ipracevpn.com     → 57.131.38.151   (Italy — primary)
it-v2ray.ipracevpn.com   → 57.131.38.151
jp-v2ray.ipracevpn.com   → 45.83.22.103    (Japan)
kz-ssh.ipracevpn.com     → 95.164.114.42   (Kazakhstan)
nl-ssh.ipracevpn.com     → 167.99.32.170   (Netherlands)
ru-ssh.ipracevpn.com     → 103.113.68.57   (Russia/Moscow)
tr-ssh.ipracevpn.com     → 94.131.123.223  (Turkey/Istanbul)
ua-ssh.ipracevpn.com     → 45.87.155.13    (Ukraine/Kyiv)
uk-ssh.ipracevpn.com     → ...             (United Kingdom)
us-ssh.ipracevpn.com     → ...             (United States)
[+ additional subdomains]
```

**Protocols per location:** SSH, V2Ray, Shadowsocks, IKEv2, Hysteria, TrojanGo, SOCKS5

### Domain registration:

```
Domain:      ipracevpn.com
Registered:  2022-12-11
Expires:     2026-12-11
Last updated: 2025-12-07
Registrar:   Name.com, Inc.
Nameservers: Cloudflare (jaime + jamie)
Privacy:     Enabled
```

Active and maintained for 3+ years.

---

## Phase 5 — Certificate Transparency Analysis

```bash
curl -s "https://crt.sh/?q=%25ipracevpn.com&output=json"
```

Returned **105 unique domains** across the full operational history.

**Key finding — protocol evolution timeline:**

| Date | Addition | Significance |
|------|----------|--------------|
| Dec 2022 | SSH + V2Ray | Launch — 10+ servers deployed day one |
| Sep 2023 | Hysteria + TrojanGo | Chinese GFW-circumvention tools added |
| Oct 2024 | SOCKS5 | Proxy reselling infrastructure added |
| Oct–Nov 2025 | IKEv2 | Enterprise VPN protocol added |
| Feb 2026 | Active cert renewals | Still operational at time of investigation |

**Critical observation:** Hysteria and TrojanGo are tools developed specifically to bypass China's Great Firewall. Their adoption in September 2023 — across all major locations simultaneously — indicates an operator with direct familiarity with Chinese censorship circumvention tooling. This is the first significant indicator of Chinese-origin operation.

**Hidden servers revealed by certificate transparency (not in DNS enumeration):**

```
ru-ssh, ru-v2ray    (Russia)
tr-ssh, tr-v2ray    (Turkey)
ua-ssh, ua-v2ray    (Ukraine — active conflict zone)
sg-hysteria         (Singapore)
sg-trojango
us-hysteria
de-hysteria
vn-ssh              (Vietnam)
my-ssh              (Malaysia)
ph-ssh              (Philippines)
in-test, sg-test    (Test servers)
```

---

## Phase 6 — BGP and Hosting Analysis

### Active server IP resolution:

```bash
for subdomain in ru-ssh tr-ssh ua-ssh sg-hysteria us-hysteria de-hysteria; do
  result=$(curl -s "https://dns.google/resolve?name=${subdomain}.ipracevpn.com&type=A")
  echo "${subdomain}.ipracevpn.com → $(echo $result | python3 -c "import json,sys; [print(a['data']) for a in json.load(sys.stdin).get('Answer',[]) if a.get('type')==1]")"
done
```

```
| ru-ssh.ipracevpn.com | 103.113.68.57 | Moscow, Russia | UFO Hosting AS33993 | SSH, V2Ray |
| tr-ssh.ipracevpn.com | 94.131.123.223 | Istanbul, Turkey | UFO Hosting AS33993 | SSH, V2Ray |
| ua-ssh.ipracevpn.com | 45.87.155.13 | Kyiv, Ukraine | WorkTitans AS209847 | SSH, V2Ray |
sg-hysteria           → 170.187.196.27  (Singapore, Linode/Akamai)
us-hysteria           → 104.200.17.237  (Texas, Linode/Akamai)
de-hysteria           → 143.42.49.39    (Frankfurt, Linode/Akamai)
```

### Hosting provider analysis:

**WorkTitans B.V. (AS209847):**
- Dutch registered company (B.V. = Dutch corporate structure)
- IP blocks registered in **Moldova** — a known bulletproof hosting jurisdiction
- Serves both Turkey and Ukraine servers — geopolitically sensitive regions
- Route announced October 2025 — relatively recent
- Classification: bulletproof hosting provider

**UFO Hosting LLC (AS33993):**
- Russian hosting provider, Moscow
- IP blocks also registered in **Moldova**
- Classification: Russian hosting with Moldovan IP registration

**Moldova IP registration pattern:**
Both providers register IP blocks in Moldova despite physical servers elsewhere. Moldova has minimal cybercrime enforcement infrastructure, meaning abuse reports are routinely ignored. This is a deliberate choice to avoid accountability.

**Infrastructure provider diversity (deliberate):**
```
OVH (France)           — SSH cluster servers
UFO Hosting (Russia)   — Moscow server
WorkTitans (Moldova/NL)— Turkey, Ukraine servers
Linode/Akamai          — Hysteria servers
DigitalOcean           — IKEv2 servers
```

Five different providers across multiple jurisdictions. Single-provider hosting would create a single point of failure and a single abuse contact. Deliberate diversification indicates operational security awareness.

### Additional finding — Server Management Panel

A reverse IP lookup on `94.131.123.223` (WorkTitans B.V., Turkey) revealed a co-hosted domain:
```
kynastore.my.id         → 94.131.123.223
pterodactyl.kynastore.my.id → 94.131.123.223
n.pterodactyl.kynastore.my.id → 94.131.123.223
```

`pterodactyl.kynastore.my.id` is a Pterodactyl server management panel — an open-source tool commonly used to manage fleets of VPS nodes. Its presence on the same IP as a core ipracevpn.com relay indicates centralized fleet management. `kynastore.my.id` was registered 2025-08-14 via Domainesia (Indonesian registrar).

Confidence: MEDIUM — co-hosting confirmed, operational role inferred.

---

## Phase 7 — Chinese Domain Connection

### Reverse IP lookup on Australian server:

```bash
curl -s "https://api.hackertarget.com/reverseiplookup/?q=170.64.161.189"
```

```
whv.fanxingjiaoyu.com
au-ss.ipracevpn.com
au-ssh.ipracevpn.com
au-v2ray.ipracevpn.com
```

A Chinese domain — `fanxingjiaoyu.com` (翻星教育, "foreign star education") — resolves to the same IP as the Australian ipracevpn servers.

### Full subdomain enumeration of the Chinese domain:

```bash
curl -s "https://api.hackertarget.com/hostsearch/?q=fanxingjiaoyu.com"
```

```
fanxingjiaoyu.com         → 170.64.161.189
whv.fanxingjiaoyu.com     → 170.64.161.189
whv1.fanxingjiaoyu.com    → 170.64.161.189
whv2.fanxingjiaoyu.com    → 170.64.161.189
whv3.fanxingjiaoyu.com    → 170.64.161.189
whv4.fanxingjiaoyu.com    → 170.64.161.189
whv5.fanxingjiaoyu.com    → 170.64.161.189
whv6.fanxingjiaoyu.com    → 170.64.161.189
whv7.fanxingjiaoyu.com    → 170.64.161.189
mail.fanxingjiaoyu.com
```

### Chinese domain registration:

```
Domain:     fanxingjiaoyu.com
Created:    2025-04-04
Expires:    2026-04-04
Registrar:  Xin Net Technology Corporation (Chinese registrar)
Phone:      +86.4008182233
Nameservers: Cloudflare
```

### Russian server reverse lookup:

```bash
curl -s "https://api.hackertarget.com/reverseiplookup/?q=103.113.68.57"
```

```
chinesecleaning.ru
www.chinesecleaning.ru
chn-dreamcreation.ru
www.chn-dreamcreation.ru
dgshuangxin.ru          (双鑫 — Chinese company name)
www.dgshuangxin.ru
juliengineering.ru
paperpackaging.ru
szwyoo.ru               (SZ = likely Shenzhen)
xingyiyuan.ru           (兴义源 — Chinese company name)
```

Every domain sharing the Moscow SSH server is a Chinese business operating in Russia.

---

## Findings Summary

### Confirmed:

| Finding | Evidence |
|---------|----------|
| Foreign operation on Egyptian carriers since Dec 2022 | Domain registration date, certificate history |
| Traffic routing through foreign servers | ipinfo.io exit node confirmation |
| HWID collection from Egyptian devices | App UI screenshot |
| 48+ servers across 20+ countries | hostsearch enumeration |
| 105 domains across 3-year history | crt.sh certificate transparency |
| Chinese-origin tooling (Hysteria, TrojanGo) | Certificate timeline, Sep 2023 deployment |
| Chinese domain on shared infrastructure (MEDIUM — shared hosting unconfirmed) | fanxingjiaoyu.com reverse IP |
| Russian server hosting Chinese businesses | Moscow IP reverse lookup |
| Moldovan bulletproof hosting | BGP/ASN analysis |
| Deliberate provider diversification | 5 different hosting providers |
| Operation active at time of investigation | Active cert renewals Feb 2026 |

### Assessment:

This is not a hobbyist free-internet project. The infrastructure scale (48+ servers, 5 hosting providers, 20+ countries, 3-year operation), protocol diversity (SSH/V2Ray/Shadowsocks/IKEv2/Hysteria/TrojanGo/SOCKS5), Chinese-origin tooling deployment, bulletproof hosting choices, and HWID collection system indicate an organized foreign operation with financial backing and operational security awareness.

Traffic routing through foreign servers constitutes a proven interception capability. Whether that capability is actively exercised against Egyptian user data remains unconfirmed by this investigation. Attribution to a specific actor or state remains ongoing.

The free internet offering to Egyptian users is the user acquisition layer. The traffic interception capability and HWID collection represent the actual product.

---

## Infrastructure Map

| Subdomain | IP | Location | Provider | Protocol |
|-----------|-----|----------|----------|----------|
| it-ssh.ipracevpn.com | 57.131.38.151 | Milan, Italy | OVH AS16276 | SSH, V2Ray |
| ru-ssh.ipracevpn.com | 103.113.68.57 | Moscow, Russia | UFO Hosting AS33993 | SSH, V2Ray |
| tr-ssh.ipracevpn.com | 94.131.123.223 | Istanbul, Turkey | UFO Hosting AS33993 | SSH, V2Ray |
| ua-ssh.ipracevpn.com | 45.87.155.13 | Kyiv, Ukraine | WorkTitans AS209847 | SSH, V2Ray |
| sg-hysteria.ipracevpn.com | 170.187.196.27 | Singapore | Linode/Akamai | Hysteria |
| us-hysteria.ipracevpn.com | 104.200.17.237 | Texas, USA | Linode/Akamai | Hysteria |
| de-hysteria.ipracevpn.com | 143.42.49.39 | Frankfurt, Germany | Linode/Akamai | Hysteria |
| au-ssh.ipracevpn.com | 170.64.161.189 | Australia | — | SSH, V2Ray, SS |
| de-ikev2.ipracevpn.com | 207.154.242.101 | Germany | DigitalOcean | IKEv2 |

---

## Indicators of Compromise (IOCs)

### IP Addresses:
```
57.131.38.151    — Primary exit node (Italy/OVH)
103.113.68.57    — Russia (UFO Hosting)
94.131.123.223   — Turkey (WorkTitans)
45.87.155.13     — Ukraine (WorkTitans)
170.187.196.27   — Singapore Hysteria (Linode)
104.200.17.237   — US Hysteria (Linode)
143.42.49.39     — Germany Hysteria (Linode)
170.64.161.189   — Australia (shared with Chinese domain)
207.154.242.101  — Germany IKEv2 (DigitalOcean)
```

### Domains:
```
ipracevpn.com             — Primary operator domain
fanxingjiaoyu.com         — Chinese domain on shared infrastructure
*.ipracevpn.com           — 48 active subdomains
whv[1-7].fanxingjiaoyu.com — Chinese domain subdomains
```

### SSH Fingerprint:
```
9e:bc:6b:aa:4d:48:f5:d1:54:c6:f0:4e:7c:2b:ff:39
```

### Telegram channel:
```
Telegram (channel name withheld — provided to authorities)
```

---

## Tools Used

All tools used are free and publicly available. No unauthorized access was performed at any stage.

| Tool | Purpose |
|------|---------|
| HTTP Custom (Android app) | Initial config analysis, connection logging |
| Termux (Android) | Network commands on mobile |
| `curl` + `ipinfo.io` | Exit node identification |
| `nmap` | Port scan and service detection |
| `api.hackertarget.com` | Reverse IP lookup, hostsearch |
| `crt.sh` | Certificate transparency log analysis |
| `dns.google` (DoH) | DNS resolution through Tor |
| `rdap.verisign.com` | Domain registration data |
| `ip-api.com` | IP geolocation and ASN data |
| Team Cymru whois | BGP/ASN analysis |
| `api.bgpview.io` | ASN details and prefix data |
| Kali Linux | Advanced enumeration phases |
| Tor (torsocks) | Anonymized queries |

---

## Disclosure Timeline

| Date | Action |
|------|--------|
| March 17, 2026 | Investigation conducted (Termux + Android) |
| March 17, 2026 | Formal report submitted to EG-CERT via email and online form |
| March 17–18, 2026 | Extended investigation on Kali Linux |
| March 18, 2026 | Full technical report completed |
| March 20, 2026 | Public disclosure (this document) |

**Disclosure contacts:**
- EG-CERT: incident@egcert.eg
- NTRA: info@tra.gov.eg
- OVH Abuse: abuse@ovh.net (pending)

---

## Methodology Note

This investigation was conducted entirely using free public tools from a mobile device (Android/Termux) and a personal laptop (Kali Linux). No proprietary tools, institutional resources, or unauthorized access was used at any stage. All data was gathered from publicly accessible APIs and registries.

The investigation started from a single encrypted configuration file shared on social media and arrived at a complete infrastructure map of a 3-year operation spanning 20+ countries — using only tools available to any researcher with a phone and an internet connection.

---

*Amir Elbelawy — Computer & Communications Engineering, Mansoura University*  
*Al Mahallah al Kubra, Al Gharbiyah, Egypt*  
*March 2026*
