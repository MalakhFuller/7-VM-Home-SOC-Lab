# Home SOC Lab — Build & Defend, Attack & Detect

If you've scrolled through a few home-lab repos, you know the genre: a clean Wazuh install, three green checkmarks, a screenshot of an alert firing, done. Everything works on the first try. Nobody ever types the wrong password, points a sensor at the wrong interface, or spends twenty minutes staring at an empty search wondering where their data went.

That's not this repo. This is the version with the dead ends left in.

I'm a career-changer moving into detection and SOC work after about twenty years in human-intelligence-driven competitive intelligence research — as a desk analyst and client-facing consultant. The job was directing researchers who got people on the phone talking, then doing the part that actually mattered: reviewing what came back, pushing for a second and third independent source before I'd believe it, and turning it into briefings executives and clients made real decisions on. So I'll be straight about where I stand: I'm new to the tooling, but I'm not new to the *thinking*. The instinct to verify before you trust, to take a broken chain apart one link at a time, to corroborate a finding against a second source before you bank on it, to decide an avenue isn't worth grinding on and reroute cleanly — none of that is new. It's the analytical half of the job I already had, pointed at a different target. This lab is where I'm welding the two together, and writing down every place the weld didn't hold the first time.

---

## How to read this repo

The work follows an intrusion the way it actually unfolds: build the instrument first, then walk the kill chain one step at a time — gain a foothold, escalate, move.

1. **[The Lab Buildout](./soc-lab-infrastructure-buildout.md)** — the dual-SIEM + network-IDS environment everything else runs on. It's the foundation the rest builds on; start here.
2. **[Password Spraying a No-Lockout Domain](./password-spraying-dual-siem-detection.md)** — the initial foothold. Catching a loud spray in both SIEMs, then defeating those same detections with a low-and-slow spray that exposes where each SIEM's architecture wins and loses — including telling a real spray apart from a Monday-morning password-reset storm (MITRE ATT&CK [T1110.003](https://attack.mitre.org/techniques/T1110/003/)).
3. **[Kerberoasting on an AES-Only Domain](./kerberoasting-aes-roast-dual-siem-detection.md)** — credential access after a foothold. Why the textbook RC4 detection is blind on a hardened Server 2025 domain, and the behavioral rule that catches it in both SIEMs (MITRE ATT&CK [T1558.003](https://attack.mitre.org/techniques/T1558/003/)).
4. **Lateral Movement** — _planned_ — the capstone: moving across the domain once you're in.

Each writeup is self-contained and built for two readers: a narrative with the reasoning and the dead ends left in, then a copy-paste **reference appendix** with the working detections and a scope note on what they do and don't catch. Read the story if you're evaluating how I think; jump to the appendix if you just need the rule.

Alongside the writeups: config artifacts, the hand-built CIM add-on (`TA-suricata-cim`), and screenshots documenting each step — including the ones where it wasn't working yet.

---

## The lab at a glance

| VM | Role | IP |
|---|---|---|
| Kali-AttackBox | Attack simulation | 10.10.10.128 |
| WazuhServer-SIEM01 | SIEM #1 / XDR (Wazuh 4.14) | 10.10.10.130 |
| Win11-Victim01 | Windows endpoint + Sysmon | 10.10.10.131 |
| Ubuntu-Victim02 | Linux endpoint | 10.10.10.133 |
| WinServer-DC01 | Domain controller (`soclab.local`) | 10.10.10.134 |
| Splunk-SIEM02 | SIEM #2 (Splunk Enterprise) | 10.10.10.137 |
| Suricata-Sensor01 | Passive network IDS | 10.10.10.140 |

All seven VMs sit on an isolated `10.10.10.0/24` segment. Telemetry from the three endpoints and one network sensor lands in both Wazuh and Splunk.

---

## What makes it more than another Wazuh box

Three things, and they're the three I'd want to be asked about:

- **Dual SIEM.** Wazuh and Splunk running side by side against identical telemetry. Same events, two platforms, so I can build the same detection twice and learn where each tool thinks differently.
- **One sensor, two sets of eyes.** A passive Suricata IDS sniffing the wire in promiscuous mode, with its alerts shipped into *both* SIEMs — verified end-to-end with a real nmap detection, not assumed from a status light.
- **Hand-mapped CIM.** Instead of installing a vendor add-on to normalize Suricata's data, I wrote the mapping myself — field aliases, EVAL logic, eventtype and tag definitions, the cross-app metadata export — and validated it against Splunk's live Common Information Model spec until the Intrusion Detection data model claimed my sensor's events as its own. That's the difference between data being *present* and data being *usable*, and I wanted to understand it from the inside rather than trust a black box.

---

## The lessons that stuck

The full list is in each writeup, but these are the ones I'll carry into a real SOC:

- **A config edit and a service reload are two different actions.** Half the "but I configured it!" problems in this field are really "you configured it and never made anything reload it."
- **When a test comes back empty, walk the chain from the source out.** Confirm the thing at the start actually fired before blaming anything downstream.
- **The absence of an error is information.** Empty-and-not-complaining means a process never *tried* — which points somewhere different than a process that tried and failed.
- **Verify the wire before you trust the wire.** One `tcpdump` command, run before I built anything, was the foundation the whole sensor build stood on.
- **Verify prior-session assumptions against live reality.** What's true in your notes can be false on the box. The live error wins, every time.

---

## What's next

The instrument is built and verified, and the attacks are underway. Password spraying and Kerberoasting (above) are both run through it end to end — each ending in custom detection rules written in both SIEMs, including the contrast between a loud attack and a patient one. Lateral movement is next, building toward a full purple-team capstone with a real incident report.

That's where this lab stops being a thing I built and starts being a thing I can defend — attack by attack, detection by detection.

I came up not trusting a single report until a second source backed it up. Turns out a SIEM pipeline is no different: prove every link, trust nothing you haven't checked yourself, and write down where it broke so it doesn't break you twice.

---

## Author

**Malakh Fuller** — [LinkedIn](https://www.linkedin.com/in/malakhfuller/) · [GitHub](https://github.com/MalakhFuller)

*CompTIA A+ · Network+ · Security+ · CySA+ (in progress) · transitioning into SOC analysis and detection engineering after twenty years in human-intelligence-driven competitive intelligence research.*
