# Home SOC Lab — Dual-SIEM Infrastructure Build-Out

If you've scrolled through a few home-lab repos, you know the genre: a clean Wazuh install, three green checkmarks, a screenshot of an alert firing, done. Everything works on the first try. Nobody ever types the wrong password, points a sensor at the wrong interface, or spends twenty minutes staring at an empty search wondering where their data went.

That's not this repo. This is the version with the dead ends left in.

I'm a career-changer moving into detection and SOC work after about twenty years in HUMINT and counterintelligence. So I'll be straight about where I stand: I'm genuinely new to the tooling, and I'm not new to the *thinking*. The instinct to verify access before you trust the take, to take a broken chain apart one link at a time, to decide an avenue isn't worth grinding on and reroute cleanly — that part isn't new. That's the job I already had, pointed at a different target. This lab is where I'm welding the two together, and writing down every place the weld didn't hold the first time.

---

## What this is

A seven-VM home SOC lab built from scratch inside VMware Workstation Pro on a single host, on a fully isolated network. It's not a single-SIEM tutorial box. By the end it runs **two SIEMs in parallel**, a **passive network IDS feeding both of them**, and a **normalization layer I hand-wrote** so the sensor's data actually speaks the same language as everything else.

The whole thing is the instrument. The *next* project is me attacking it.

### The lab at a glance

| VM | Role | IP |
|---|---|---|
| Kali-AttackBox | Attack simulation | 10.10.10.128 |
| WazuhServer-SIEM01 | SIEM #1 / XDR (Wazuh 4.14) | 10.10.10.130 |
| Win11-Victim01 | Windows endpoint + Sysmon | 10.10.10.131 |
| Ubuntu-Victim02 | Linux endpoint | 10.10.10.132 |
| WinServer-DC01 | Domain controller (`soclab.local`) | 10.10.10.134 |
| Splunk-SIEM02 | SIEM #2 (Splunk Enterprise) | 10.10.10.137 |
| Suricata-Sensor01 | Passive network IDS | 10.10.10.140 |

All seven on an isolated `10.10.10.0/24` segment. Telemetry from three endpoints and one network sensor lands in both Wazuh and Splunk.

---

## What makes it more than another Wazuh box

Three things, and they're the three I'd want to be asked about:

- **Dual SIEM.** Wazuh and Splunk running side by side against identical telemetry. Same events, two platforms, so I can build the same detection twice and learn where each tool thinks differently.
- **One sensor, two sets of eyes.** A passive Suricata IDS sniffing the wire in promiscuous mode, with its alerts shipped into *both* SIEMs — verified end-to-end with a real nmap detection, not assumed from a status light.
- **Hand-mapped CIM.** Instead of installing a vendor add-on to normalize Suricata's data, I wrote the mapping myself — field aliases, EVAL logic, eventtype and tag definitions, the cross-app metadata export — and validated it against Splunk's live Common Information Model spec until the Intrusion Detection data model claimed my sensor's events as its own. That's the difference between data being *present* and data being *usable*, and I wanted to understand it from the inside rather than trust a black box.

---

## What's in this repo

- **[`soc-lab-infrastructure-buildout.md`](./soc-lab-infrastructure-buildout.md)** — the full writeup. Every phase, every wall I hit, every recovery. If you only read one file, read that one.
- Config artifacts and the hand-built CIM add-on (`TA-suricata-cim`).
- Screenshots documenting each step, including the ones where it wasn't working yet.

The writeup is deliberately honest about the friction: the cloud-EDR trial that tripped a fraud hold and got deferred, the silent-typo lockout that cost an evening, the host field that bit me three separate times before I learned it's the real computer name and not the VM label, the dead pipe between the sensor and the second SIEM that came down to one un-reloaded config file, and the "data model not found" error that turned out to be a missing base add-on I'd *assumed* was installed. None of that is in here to look humble. It's in here because the troubleshooting is the part that actually transferred to skill, and the clean-screenshot version would have hidden exactly the thing worth showing.

---

## The lessons that stuck

The full list is in the writeup, but the ones I'll carry into a real SOC:

- **A config edit and a service reload are two different actions.** Half the "but I configured it!" problems in this field are really "you configured it and never made anything reload it."
- **When a test comes back empty, walk the chain from the source out.** Confirm the thing at the start actually fired before blaming anything downstream.
- **The absence of an error is information.** Empty-and-not-complaining means a process never *tried* — which points somewhere different than a process that tried and failed.
- **Verify the wire before you trust the wire.** One tcpdump command, run before I built anything, was the foundation the whole sensor build stood on.
- **Verify prior-session assumptions against live reality.** What's true in your notes can be false on the box. The live error wins, every time.

---

## What's next

The infrastructure is built and verified. The next project moves from *building* the instrument to *using* it — populating Active Directory with realistic targets (including a Kerberoastable service account, because a vanilla domain has nothing to roast), confirming the DC actually generates the telemetry the attacks should produce, and then running them: password spray, Kerberoasting, lateral movement, custom detection-rule writing in both SIEMs, and a full purple-team capstone with a real incident report.

That's where this lab stops being a thing I built and starts being a thing I can defend — attack by attack, detection by detection.

I came up verifying access before I banked on what a source could give me. Turns out a SIEM pipeline is no different: prove every link, trust nothing you haven't checked yourself, and write down where it broke so it doesn't break you twice.

---

## Author

**Malakh Fuller** — [LinkedIn](https://www.linkedin.com/in/malakhfuller/) · [GitHub](https://github.com/MalakhFuller)

*Security+ · CySA+ (in progress) · transitioning into detection engineering and SOC analysis from a HUMINT/CI background.*
