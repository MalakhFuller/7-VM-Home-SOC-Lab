# SOC Lab Infrastructure Build-Out: 7 VMs | Dual SIEM | Network IDS | CIM Normalization

**Completed:** 2026-06-18

**Author:** Malakh Fuller

> **Privacy note:** Internal lab IP addresses have been anonymized in this writeup and related screenshots. All testing was performed exclusively on my own isolated home lab network.

> **How to read this:** This is the honest version. Where I hit a wall, took a wrong turn, or assumed something was working when it wasn't, that's in here on purpose. A writeup where everything works the first time is a writeup where nothing was actually learned. The dead ends *are* the experience — they're the part I can defend in an interview, because I lived them.

> **On AI:** I used Claude as a research partner in this lab build — to pressure-test my reasoning and rapidly turn lengthy session notes into clean prose. AI accelerated the work without question. That said: every command was one I ran, every wall was one I hit myself, and every claim made here I can defend with the tab closed. I would still have achieved every objective without AI. It would have simply taken a far longer time horizon. If a tool lets me finish in three hours what might otherwise take three weeks of trawling forum threads, I'd be silly not to use it. Both paths succeed — but in a field where the offensive and defensive ground shifts weekly, that efficiency can make all the difference. Or, to put it in relatable real-world terms: a carpenter who refuses to use power tools can still build things, but it'll take a lot longer — and not many people will want to hire them.

---

## Objective

Take the 5-VM Wazuh lab I'd already built and turn it into the kind of environment a real SOC actually runs: a **second SIEM** alongside the first, a **network intrusion detection sensor** watching the wire, and a **normalization layer** that makes raw sensor data speak the same field language as everything else.

Concretely, that meant four things on top of the existing foundation:

1. Stand up **Splunk Enterprise** as a second SIEM running in parallel with Wazuh — the SIEM that shows up most in job postings — and forward every endpoint into it.
2. Build a **passive Suricata IDS sensor** that sniffs the lab segment and detects network-layer attacks the endpoint agents can't see.
3. Feed that one sensor into **both** SIEMs, so Wazuh and Splunk are watching the same network detections.
4. Hand-write a **CIM (Common Information Model) mapping** so Suricata's data lands in Splunk's Intrusion Detection data model instead of sitting in an un-normalized pile — the difference between "the data is technically there" and "the data is usable."

The goal was never to follow a tutorial to a working screenshot. It was to build the instrument I'll spend the *next* project attacking, and to understand every layer well enough that when something breaks mid-investigation later, I already know where the pipe runs.

---

## Tools and Technologies

| Category | Details |
|---|---|
| **Hypervisor** | VMware Workstation Pro (Broadcom, free for personal use) |
| **SIEM #1 / XDR** | Wazuh 4.14 (Manager, Indexer, Dashboard) |
| **SIEM #2** | Splunk Enterprise 10.4.0 (Developer License, 10GB/day) |
| **Network IDS** | Suricata 8.0.x (OISF stable PPA), ET Open ruleset (~50,750 rules) |
| **Log Forwarding** | Wazuh Agent 4.14.5, Splunk Universal Forwarder 10.x |
| **AttackBox** | Kali Linux 2026.1 |
| **Victim Endpoints** | Windows 11 Enterprise (Evaluation), Ubuntu Server (LTS) |
| **Domain Controller** | Windows Server 2025 (Evaluation), AD DS for `soclab.local` |
| **Endpoint Telemetry** | Sysmon v15.20 (SwiftOnSecurity config) |
| **Normalization** | Splunk Common Information Model Add-on + hand-built `TA-suricata-cim` |
| **Skills Applied** | PowerShell, Linux CLI, Active Directory, network segmentation, log forwarding, SPL, props/transforms config, CIM data modeling |
| **Prior Knowledge** | CompTIA A+, Network+, Security+, CySA+ (in progress), prior home SOC labs |

---

## Final VM Roster

Seven VMs running concurrently on a single host (Ryzen 9 9950X / 64GB DDR5), all on the isolated `10.10.10.0/24` segment.

| VM | Role | IP | RAM | vCPU |
|---|---|---|---|---|
| Kali-AttackBox | Attack simulation | 10.10.10.128 | 4GB | 2 |
| WazuhServer-SIEM01 | SIEM #1 / XDR | 10.10.10.130 | 8GB | 4 |
| Win11-Victim01 | Windows endpoint (`DESKTOP-6H1BPIU`) | 10.10.10.131 | 6GB | 2 |
| Ubuntu-Victim02 | Linux endpoint | 10.10.10.133 | 2GB | 2 |
| WinServer-DC01 | Domain controller (`WIN-CBG93HEA6LI`) | 10.10.10.134 | 4GB | 2 |
| Splunk-SIEM02 | SIEM #2 | 10.10.10.137 | 8GB | 4 |
| Suricata-Sensor01 | Passive network IDS | 10.10.10.140 | 4GB | 2 |

---

## Network Architecture

| Network | Purpose | Subnet |
|---|---|---|
| VMnet2 | SOC internal — all VMs, fully isolated | 10.10.10.0/24 |
| VMnet8 (NAT) | Temporary internet, removed/toggled after installs | 192.168.x.x/24 |

Everything lives on the isolated `VMnet2` segment. The two infrastructure boxes that need to pull updates from the internet — Splunk and the Suricata sensor — are **deliberately dual-homed** (a second NAT adapter) rather than giving the whole lab internet. That's a conscious trade: a dual-homed box bridges the isolated network to the outside, so I kept the bridge on the SIEM/sensor (saner places to allow internet) and off the victims and the attacker box. The NAT adapters are toggleable if I want pure isolation for a given attack scenario later.

---

## The Foundation (Prior Work, Condensed)

This build sits on top of a 5-VM Wazuh lab I'd already stood up: VMware Workstation Pro, an isolated `VMnet2`, Kali, a Wazuh manager/indexer/dashboard, two domain-joined victims (Windows 11 + Ubuntu), and a Windows Server 2025 domain controller running `soclab.local` with Sysmon on the Windows boxes.

A few things from that foundation are worth carrying forward because they bit me then and inform everything here:

- **VMware custom networks don't appear in the VM adapter dropdown** until you check *"Connect a host virtual adapter to this network"* in the Virtual Network Editor. The networks exist on paper but the VMs can't select them. Pure troubleshooting to discover — it's documented nowhere obvious.
- **Linux can join a Windows AD domain** (`realmd` + `sssd` stack), but the join fails until you point the Linux box's DNS resolver at the domain controller. In a mixed-OS environment, DNS is the foundation everything else stands on.
- **Wazuh starts detecting vulnerabilities the moment an agent connects** — 7 CVEs surfaced on the Windows endpoint within minutes, zero config. And **Sysmon flags all your own admin activity as suspicious**, which was my first real lesson in false positives: the same alerts that fire on legitimate setup work will fire on a real attack, and telling them apart is the actual job.

With that foundation live, Phase 2 begins.

---

## The Build

### 1. The MDE dead end, and knowing when to resequence

The plan opened with Microsoft Defender for Endpoint: deploy it across the lab and pull its telemetry into Wazuh. I got the architecture straight first — MDE is a *cloud* EDR, so onboarded endpoints report to Microsoft's cloud, and "telemetry into Wazuh" actually means Wazuh reaching *out* to the Graph API to pull alerts back down. Fine. Then I hit gate after gate:

- No free standalone MDE — the path is a trial tied to a Microsoft 365 tenant. I created a *dedicated, lab-only* Microsoft account to keep the lab identity walled off from anything real (compartmentalization, the right habit when the environment will be generating attack telemetry).
- The trial demanded a credit card even at $0. Plan was: enter card, immediately kill auto-renew.
- The order tripped a **fraud hold (error 43881)** and the billing account came back **Disabled**. A brand-new account instantly buying enterprise security licensing looks exactly like fraud to an automated risk engine, so it got kicked to a human review on Microsoft's clock — hours to days.

So I made a call: **defer MDE, don't grind on it.** It threw up two hard gates and produced zero hands-on learning, and it wasn't load-bearing for anything downstream — it was first on the list only because of how I'd ordered things. Meanwhile every other tool in the plan installs locally with none of that friction. The tenant stays parked (no charge, billing never activated) and is reusable later for Microsoft Sentinel if I go that way. The evening wasn't wasted; I stood up a tenant I can repurpose, and I pivoted to the tool recruiters actually ask about: Splunk.

That decision discipline is the same muscle from twenty years in competitive intelligence: when a line of inquiry stops paying out, you don't keep a researcher digging it out of stubbornness — you read where the resistance is, decide whether the objective actually depends on this avenue, and redirect without losing the goal. Knowing when to abandon a line cleanly is its own skill.

### 2. Standing up Splunk — and a lockout that cost me an evening

I chose to run Splunk on **Ubuntu Server, headless**, not Windows and not a desktop — because in production it runs on Linux, administered over SSH, and I want my hands to match what a real shop runs. Developer License (10GB/day, no trial clock) so it's free and persistent.

Then, before I installed a single thing, the build nearly died on the dumbest possible problem: I finished the Ubuntu install, went to log in, and got **"Login incorrect"** — repeatedly, with a password I was sure of. Rather than guess, I worked it:

- Confirmed Linux hides the password field entirely as you type, so a typo is silent.
- Ruled out Caps Lock and case sensitivity.
- Ran a **keyboard-layout test** — typed the password into the *visible* username field just to see it render. It came out correct, so the keyboard mapped fine; layout wasn't the problem.
- Confirmed from the boot banner I was in the installed system, not the installer.

Conclusion: a silent typo when I *set* the password during install. The password I set wasn't the password I thought I set. I tried the proper sysadmin recovery (GRUB → root shell → `passwd`), but couldn't reliably catch the GRUB menu in the VM, and with an empty box and nothing to save, I took the pragmatic off-ramp: delete and rebuild, writing the password down *before* typing it this time. A 30-second habit that would have saved an hour. The rebuild logged in first try.

The install itself, once I was in:

- `.deb` package transferred via VMShare (headless box, no GUI to drag into — and shared folders are *per-VM* in VMware, so the host folder existing wasn't enough; I had to enable it in this VM's options and mount it by hand).
- First start refused outright: *"Running Splunk Enterprise as root is deprecated."* Instead of forcing it, I set up the proper fix **before** first start — created an unprivileged `splunk` user, `chown`'d `/opt/splunk` to it, started under `sudo -u splunk`. The reasoning: first start creates all the runtime files, and whoever creates them owns them. Doing the service account first means a clean ownership foundation and least-privilege done right — a Splunk compromise lands on a limited account, not root.
- The box is dual-homed: `ens33` (10.10.10.137, VMnet2) is the **collection** address forwarders ship to; `ens34` (NAT) is for pulling Splunkbase add-ons. Console reached from my *host* browser at `:8000` — with one false start where I pasted the URL into the VM's terminal and bash tried to run it as a command.

Splunk Enterprise live.

![Splunk Enterprise — Hello, Administrator](screenshots/02_Splunk-is-deployed.jpg)
*The Splunk web console, reached from the host browser at `:8000` — the second SIEM is up and reachable.*

<!-- OPTIONAL (01): first-start terminal showing "The Splunk web interface is at..." — ![Splunk first start](screenshots/01_Splunk-is-installed.jpg) -->

### 3. Wiring the endpoints into Splunk — three rounds of the same lesson

Getting Universal Forwarders onto all three endpoints (the DC, Win11, Ubuntu) was where I learned what real forwarder troubleshooting looks like — mostly by getting the same lesson three times until it stuck.

**The host-name lesson (bit me three times).** Every time I searched for data by the name I'd given the VM — `WinServer-DC01`, `Win11-Victim01` — I got nothing, and briefly thought the forward was broken. It wasn't. **Splunk's `host` field is the machine's real computer name, not the VMware label.** Both Windows boxes carried throwaway auto-generated names (`WIN-CBG93HEA6LI`, `DESKTOP-6H1BPIU`) that I'd never renamed. The fix each time: drop the host filter, read the `host` facet in `index=_internal`, and there the box was, already sending. `hostname` is ground truth; the VM label is a sticky note.

![Splunk search showing the DC's real host name](screenshots/06_Splunk%20is%20configured%20and%20working%20as%20planned.jpg)
*Searching `index=* host=WIN-CBG93HEA6LI` — the DC's auto-generated computer name, not its VM label — returns 2,088 events. The machine was never renamed at promotion; Splunk's `host` field is the real computer name.*

**"Connected isn't sending."** On the DC, `splunk list forward-server` showed an active forward, but searches returned nothing. An active forward means the *pipe is open*, not that data is *flowing*. The forwarder was reaching Splunk (`index=_internal` proved it — thousands of the forwarder's own health logs), but the inputs that decide *what* to send weren't all configured. I diagnosed it by eliminating in order: destination (read `outputs.conf` directly) → connection (`_internal` events) → inputs (`inputs.conf`). Each check kills a branch instead of guessing.

![Indexer listening on port 9997](screenshots/04_Splunk%20is%20listening.jpg)
*Verifying below the UI: `ss -tlnp | grep 9997` shows `splunkd` listening on `0.0.0.0:9997` — open on all interfaces, so forwarders on VMnet2 can reach it. The dashboard says "saved"; the OS confirms "actually listening." Two different things.*

<!-- OPTIONAL (03): the Splunk UI "Receive data" page confirming port 9997 enabled — ![Receiving enabled](screenshots/03_Splunk%20listening%20on%20Port%209997.jpg) -->

**Sysmon needs a manual input.** The install wizard configures standard Windows Event Logs but never picks up Sysmon — it writes to its own dedicated channel. I added the stanza by hand to `inputs.conf` with `renderXml = true` (the format the supported add-on parses cleanly), and verified the file landed at the right path with `Get-Content` so Notepad couldn't sneak a `.txt` on the end.

![Sysmon telemetry parsed in Splunk](screenshots/07_Windows%20Sysmon%20money%20shot.jpg)
*243 Sysmon events from the DC, parsed by the add-on into the fields that matter for detection — `CommandLine`, `Image`, `ParentImage`, `Hashes`, `IMPHASH`, `IntegrityLevel`. This is the deep endpoint telemetry that makes detection work possible.*

**Protected vs. normal log channels.** On Win11, Application and System logs flowed but Security and Sysmon didn't. The tell: those two are *protected* channels, and the forwarder was running under a restricted virtual account that can read normal logs but not protected ones. I switched the service to **LocalSystem** and they appeared. (Production note: the least-privilege route is adding the service account to the *Event Log Readers* group rather than granting full LocalSystem.)

**Front-loading the lesson.** By the time I got to the Ubuntu endpoint, the whole point was to *apply* what Win11 taught me instead of rediscovering it. Linux has the same protected-log problem with a different mechanism — `auth.log` and `syslog` are readable by `root` and the `adm` group. So *before* first start I created a dedicated `splunkfwd` user, `chown`'d the forwarder directory to it, and added it to `adm`. Data flowed on first start, no debugging. That single up-front step *was* the entire Win11 debugging session, collapsed into one line. That's the whole reason I keep these notes.

I also installed the parsing add-ons (**Splunk Add-on for Microsoft Windows**, **Splunk Add-on for Sysmon** — the Splunk-supported one, not the archived community look-alike with the nearly identical name), kept the DC **single-homed** (multi-homing a domain controller risks DNS registration conflicts that can break AD resolution), and registered Splunk for **boot-start as the `splunk` service account** — then actually rebooted to confirm it came back on its own, rather than trusting the config. Behavior verified, not just configured.

All three endpoints now feed **both** SIEMs. The endpoint layer of the dual-SIEM is complete.

<!-- OPTIONAL (05): Splunkbase add-ons installed (Sysmon 5.0.0 + Microsoft Windows 10.0.1, both Global/Enabled) — ![Parsing add-ons](screenshots/05_Splunk%20parsing%20layer%20in%20place.jpg) -->
<!-- OPTIONAL (08): Splunk indexer boot-start (systemctl status Splunkd, enabled + active, owned by splunk) — ![Splunk boot-start](screenshots/08_Splunk%20enabled%20active%20running%20systemd%20autostart%20on%20boot.jpg) -->
<!-- OPTIONAL (09): Ubuntu forwarder boot-start, showing the splunkfwd least-privilege account — ![Ubuntu forwarder](screenshots/09_UbuntuVictom02_AgentActiveRunning.jpg) — promote this one to a live image if your audience is hands-on SOC managers; it shows least-privilege + persistence in one frame -->

### 4. A passive sensor on the wire — proving the wire before trusting it

The hard part of adding Suricata was never going to be installing it; it's a package, it installs. The hard part was a question I spent twenty years asking in competitive intelligence and was now asking about a network interface: *can this thing actually see what I need it to see?* Positioning is the whole game. It never mattered how good a source was if they weren't positioned to know the thing I needed — and a sensor wired to the wrong spot is the same problem in different clothes: an expensive way to watch your own reflection. So I didn't start with the tool. I started with the wire.

**Passive, not inline.** Two ways to put an IDS in a lab. *Inline* sits in the traffic path — every packet physically passes through it, so it can block (that's IPS), but it becomes a single point of failure and would mean re-plumbing my whole flat segment. *Passive* sits off to the side inspecting a *copy* of the traffic — it can see and alert but not stop. I went passive: it bolts onto the lab I already have without disturbing anything, and if it dies the lab keeps running and I just lose visibility. For a detection-focused build that's the right trade. (Honest read: passive is also the forgiving choice for someone still learning, and I'll take forgiving.)

**Proving the wire (this is the whole session).** A passive sensor's entire premise is that it can see conversations it isn't part of. That depends on two things being true at once: the NIC in promiscuous mode, and the VMware virtual switch flooding traffic to that port. Before Suricata was even configured, I made it *prove* it:

```
sudo tcpdump -i ens33 -n 'icmp and not host 10.10.10.140'
```

That filter is deliberate — ICMP only, and explicitly *not* anything to or from the sensor itself, so anything that appears is by definition a conversation between two *other* machines I have no business overhearing. Then from Kali I pinged the Splunk box, and there it was on the sensor: ICMP between two hosts that aren't me. Proof. The vSwitch is flooding unicast to my promiscuous port — the software equivalent of a SPAN/mirror port on physical gear, handed over for free.

One honest stumble: my *first* ping test targeted a box that turned out to be powered off and got nothing back — and for a second I thought the sensor was broken. It wasn't — "host unreachable" was an ARP failure (the target never answered), not a sniffing failure. The lesson is the old one in new clothes: **when collection comes up empty, confirm the source was actually transmitting before you tear apart the collector.**

**The two config lines that count.** Pulled Suricata from the OISF stable PPA to get 8.0.x, backed up the config, and made two edits that did the real work:

- **`HOME_NET = [10.10.10.0/24]`** — how Suricata knows "inside" from "outside." A huge number of rules are directional (external host probing internal = attack; the reverse may be nothing). Get HOME_NET wrong and the directional logic inverts — rules silently misfire. Defining "us" correctly is the whole foundation. (You can't model a threat to an organization until you've correctly drawn the boundary of the organization.)
- **af-packet interface `eth0` → `ens33`** — the default sniffs an interface name that doesn't exist on modern Ubuntu. Point it at the NIC I'd *verified* sees traffic.

`suricata-update` pulled the ET Open ruleset (**50,750 rules, 0 failed**), and `suricata -T` came back clean — meaning all 50k rules parsed and the config is sane *before* committing to a live run.

![Suricata running with the full ruleset](screenshots/10_Suricata_configured_active_running.jpg)
*Suricata `active (running)` on `af-packet`/`ens33` as an unprivileged `suricata` user — version 8.0.5, 50,750 rules loaded, 0 failed, "Engine started."*

**First blood.** Started the service (unprivileged `suricata` user, boot-start on), then poked it on purpose from Kali: `nmap -A -Pn` against the DC. `fast.log` lit up — **ET SCAN Possible Nmap User-Agent Observed**, Kali → the DC's WinRM port, caught red-handed. The full chain proven end-to-end: attack leaves Kali → crosses VMnet2 → `ens33` sees the copy → Suricata matches → alert written. Every link mine, verified, not assumed.

![Suricata first detection in fast.log](screenshots/11_Suricata%20working%20end%20to%20end.jpg)
*First blood: `fast.log` catches the scan — ET SCAN Possible Nmap User-Agent Observed, `10.10.10.128` (Kali) → `10.10.10.134:5985` (the DC's WinRM port), Priority 1. The sensor saw a conversation it wasn't part of and named the tool that made it.*

The caveat I want to stay honest about: `-A` tripped that signature *because* it's loud — it waves an nmap user-agent string around. A patient operator who slowed down wouldn't trip that rule at all. Signatures catch the loud and the lazy; the quiet professional is a behavioral problem you find by what's anomalous over time, not by a string match. That's the detection I actually care about building later — and it's the same instinct competitive intelligence ran on: the real picture rarely shows up in any single source, it shows up in the pattern you assemble across many of them.

**The permission lesson, carved into the wall.** Shipping Suricata to Splunk meant a fourth forwarder install, and I front-loaded the permission fix this time: added `splunkfwd` to the `suricata` group. Here's the part worth keeping — `eve.json` itself is `644`, world-readable, so on paper anyone can read it. But the *directory* it lives in is `770`. **You can't read a file inside a directory you're not allowed to traverse.** The directory is the real gate, not the file. World-readable means nothing if you can't walk in the door.

<!-- OPTIONAL (12): Suricata's Splunk forwarder boot-start (systemctl status, enabled + active, splunkfwd account) —
