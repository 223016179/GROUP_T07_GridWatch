"""
Generates a corpus of ORIGINAL, synthetic threat-intelligence advisory
texts modelled on the structure of public ICS advisories (e.g.
CISA/ICS-CERT style), but entirely authored for this project - no real
advisory text is reproduced. Each references MITRE ATT&CK for ICS-style
tactic names for downstream text-mining (Section 10).

20 advisories total (charter target: 15-30). The first 4 (ADV-2026-014,
021, 027, 033) are the original milestone set; the remaining 16 were
added to close the corpus-size gap noted in the charter and README.
"""
import json, os

OUT_DIR = "/home/claude/gridwatch/threat_intel"
os.makedirs(OUT_DIR, exist_ok=True)
TEMPLATES = [
    dict(
        id="ADV-2026-014",
        actor="Unattributed activity cluster (tracked internally as CLUSTER-BRONZE)",
        summary=(
            "Analysts observed an activity cluster abusing legitimate third-party "
            "remote-maintenance accounts to reach engineering workstations at "
            "energy-sector operators. Initial access relied on valid vendor "
            "credentials rather than exploitation, followed by credential-access "
            "tooling and staged collection of engineering-network files prior to "
            "attempts to reach historian and control-adjacent hosts."
        ),
        ttps=["Initial Access", "Credential Access", "Collection", "Lateral Movement"],
        indicators=["off-hours vendor logons", "atypical source IP for known vendor account",
                    "credential-dumping utility execution", "archive-staging utility on engineering host"],
    ),
    dict(
        id="ADV-2026-021",
        actor="Suspected supply-chain intrusion set (SCIS-4)",
        summary=(
            "A campaign targeting maintenance vendors serving industrial operators "
            "has been linked to attempts to disable host-based logging shortly "
            "after gaining a foothold, consistent with a defense-evasion objective, "
            "before pivoting toward historian and data-collection infrastructure."
        ),
        ttps=["Defense Evasion", "Discovery", "Collection"],
        indicators=["local logging service disabled shortly after logon",
                    "sequential authentication to multiple engineering workstations",
                    "unusual process lineage on jump host"],
    ),
    dict(
        id="ADV-2026-027",
        actor="Unattributed",
        summary=(
            "Reporting indicates a rise in unauthorized write attempts to "
            "programmable logic controllers reachable via compromised vendor "
            "remote-access pathways, generally clustered within 24-48 hours "
            "of initial anomalous vendor authentication, suggesting a compressed "
            "operational timeline once initial access is achieved."
        ),
        ttps=["Impair Process Control", "Inhibit Response Function"],
        indicators=["unauthorized setpoint write attempt", "process value deviation from setpoint",
                    "OT protocol traffic outside historical baseline"],
    ),
    dict(
        id="ADV-2026-033",
        actor="Unattributed",
        summary=(
            "Operators are advised that legitimate maintenance activity and "
            "early-stage compromise can present similarly in authentication logs "
            "alone; analysts should require corroboration from endpoint and "
            "OT-side telemetry before escalating a vendor session as malicious."
        ),
        ttps=["Discovery", "Collection"],
        indicators=["single-source anomaly without cross-log corroboration"],
    ),
    dict(
        id="ADV-2026-040",
        actor="Unattributed activity cluster (tracked internally as CLUSTER-COBALT)",
        summary=(
            "A cluster of intrusions against distribution-utility engineering "
            "networks has been observed beginning with phishing emails delivering "
            "a macro-enabled document, followed by execution of a living-off-the-"
            "land binary to establish persistence via a scheduled task on the "
            "initial foothold host before any attempt to move toward OT segments."
        ),
        ttps=["Initial Access", "Execution", "Persistence"],
        indicators=["macro-enabled document delivered via email", "scheduled task created outside change window",
                    "living-off-the-land binary invoked with encoded arguments"],
    ),
    dict(
        id="ADV-2026-047",
        actor="Suspected supply-chain intrusion set (SCIS-4)",
        summary=(
            "Follow-on reporting on SCIS-4 describes privilege-escalation attempts "
            "on jump hosts used by third-party maintenance vendors, exploiting "
            "locally cached administrative credentials left behind by legitimate "
            "support sessions rather than any software vulnerability."
        ),
        ttps=["Privilege Escalation", "Credential Access"],
        indicators=["reuse of cached administrative credential across sessions",
                    "local account added to administrators group outside change window"],
    ),
    dict(
        id="ADV-2026-052",
        actor="Unattributed activity cluster (tracked internally as CLUSTER-BRONZE)",
        summary=(
            "Additional CLUSTER-BRONZE activity shows the group establishing a "
            "command-and-control channel disguised as routine vendor telemetry "
            "traffic, using regular beacon intervals timed to blend with "
            "legitimate remote-maintenance polling."
        ),
        ttps=["Command and Control", "Defense Evasion"],
        indicators=["beacon interval matching legitimate vendor polling cadence",
                    "outbound traffic to domain registered within prior 30 days"],
    ),
    dict(
        id="ADV-2026-058",
        actor="Unattributed",
        summary=(
            "Multiple energy-sector operators reported discovery-phase activity "
            "consisting of systematic enumeration of engineering workstation "
            "shares and historian database schemas shortly after an anomalous "
            "vendor logon, without any immediately observed data exfiltration."
        ),
        ttps=["Discovery"],
        indicators=["sequential enumeration of network shares", "historian schema queries from non-engineering account"],
    ),
    dict(
        id="ADV-2026-063",
        actor="Suspected activity cluster (tracked internally as CLUSTER-INDIGO)",
        summary=(
            "A newly tracked cluster has been observed staging collected "
            "engineering documents into password-protected archives on jump "
            "hosts before transferring them to external infrastructure, "
            "consistent with a collection-to-exfiltration handoff."
        ),
        ttps=["Collection", "Exfiltration"],
        indicators=["password-protected archive created on jump host",
                    "large outbound transfer immediately following archive creation"],
    ),
    dict(
        id="ADV-2026-069",
        actor="Unattributed",
        summary=(
            "Analysts documented an intrusion in which the actor disabled "
            "automated alerting on a security information and event management "
            "console prior to escalating access, an inhibit-response-function "
            "technique intended to delay defender detection during later stages."
        ),
        ttps=["Inhibit Response Function", "Defense Evasion"],
        indicators=["SIEM alert rule disabled by non-administrative account",
                    "gap in alert volume preceding confirmed compromise window"],
    ),
    dict(
        id="ADV-2026-074",
        actor="Suspected supply-chain intrusion set (SCIS-4)",
        summary=(
            "Operators using the same remote-maintenance platform previously "
            "linked to SCIS-4 are advised that lateral movement in observed "
            "cases relied on pass-the-hash techniques against engineering "
            "workstations sharing a common local administrator credential."
        ),
        ttps=["Lateral Movement", "Credential Access"],
        indicators=["pass-the-hash authentication pattern across engineering hosts",
                    "shared local administrator credential reused across multiple assets"],
    ),
    dict(
        id="ADV-2026-081",
        actor="Unattributed activity cluster (tracked internally as CLUSTER-COBALT)",
        summary=(
            "CLUSTER-COBALT activity culminated, in one documented case, in an "
            "attempted impact against process availability through repeated "
            "unauthorized controller mode changes, though the attempt was "
            "interrupted before any sustained disruption occurred."
        ),
        ttps=["Impair Process Control", "Impact"],
        indicators=["unauthorized controller mode change", "repeated mode-change attempts within short interval"],
    ),
    dict(
        id="ADV-2026-088",
        actor="Unattributed",
        summary=(
            "Reporting highlights a pattern in which initial access through a "
            "compromised vendor account is followed almost immediately by "
            "execution of a credential-harvesting tool, suggesting the "
            "activity is opportunistic rather than the product of extended "
            "pre-positioning."
        ),
        ttps=["Initial Access", "Credential Access", "Execution"],
        indicators=["credential-harvesting tool execution within minutes of logon",
                    "vendor account authenticating from previously unseen source IP"],
    ),
    dict(
        id="ADV-2026-093",
        actor="Suspected activity cluster (tracked internally as CLUSTER-INDIGO)",
        summary=(
            "CLUSTER-INDIGO has been observed using a renamed system utility to "
            "evade signature-based detection while performing discovery of "
            "network topology and connected OT assets, a defense-evasion "
            "technique layered on top of routine reconnaissance."
        ),
        ttps=["Defense Evasion", "Discovery"],
        indicators=["system utility executed under a renamed binary", "network topology enumeration from engineering host"],
    ),
    dict(
        id="ADV-2026-099",
        actor="Unattributed",
        summary=(
            "Operators are advised that persistence in several reported "
            "intrusions was achieved through creation of a new local account "
            "on the engineering workstation used as the initial vendor access "
            "point, rather than through malware requiring ongoing execution."
        ),
        ttps=["Persistence"],
        indicators=["new local account created on engineering workstation", "account creation outside documented change request"],
    ),
    dict(
        id="ADV-2026-104",
        actor="Unattributed activity cluster (tracked internally as CLUSTER-BRONZE)",
        summary=(
            "A further CLUSTER-BRONZE case shows the group collecting historian "
            "trend data spanning several months prior to any attempt at "
            "process interference, suggesting reconnaissance of operational "
            "baselines as a precursor to a later impact attempt."
        ),
        ttps=["Collection", "Discovery"],
        indicators=["bulk export of historian trend data", "queries spanning multi-month historical range from non-analyst account"],
    ),
    dict(
        id="ADV-2026-110",
        actor="Suspected supply-chain intrusion set (SCIS-4)",
        summary=(
            "Analysts assess with moderate confidence that SCIS-4 has begun "
            "establishing a secondary command-and-control channel over a "
            "protocol commonly permitted through OT firewalls, in an apparent "
            "attempt to maintain access if the primary vendor-session pathway "
            "is closed."
        ),
        ttps=["Command and Control", "Persistence"],
        indicators=["secondary C2 channel over permitted OT firewall protocol",
                    "beaconing observed after primary vendor account was disabled"],
    ),
    dict(
        id="ADV-2026-115",
        actor="Unattributed",
        summary=(
            "A distribution-utility operator reported an attempted impact event "
            "in which an actor issued unauthorized commands to a remote "
            "terminal unit; the attempt was detected and blocked by protocol-"
            "aware monitoring before any setpoint change was accepted by the "
            "field device."
        ),
        ttps=["Impact", "Impair Process Control"],
        indicators=["unauthorized RTU command rejected by protocol monitor", "command source outside authorized engineering range"],
    ),
    dict(
        id="ADV-2026-121",
        actor="Suspected activity cluster (tracked internally as CLUSTER-INDIGO)",
        summary=(
            "CLUSTER-INDIGO's initial-access technique in two reported cases "
            "involved exploitation of a exposed remote-desktop service on a "
            "vendor jump host rather than credential compromise, followed by "
            "the same archive-staging behaviour observed in earlier reporting."
        ),
        ttps=["Initial Access", "Collection"],
        indicators=["exposed remote-desktop service reachable from external network",
                    "archive-staging utility execution matching prior CLUSTER-INDIGO reporting"],
    ),
    dict(
        id="ADV-2026-128",
        actor="Unattributed",
        summary=(
            "Operators are reminded that early indicators of vendor-account "
            "misuse are frequently subtle and single-source; sustained "
            "monitoring correlating authentication, endpoint, and OT-side "
            "telemetry remains the most reliable basis for escalation, "
            "consistent with prior guidance in this advisory series."
        ),
        ttps=["Discovery", "Collection"],
        indicators=["low-confidence single-source anomaly requiring cross-log correlation before escalation"],
    ),
]

for t in TEMPLATES:
    text = (
        f"Advisory {t['id']}\n"
        f"Threat actor / activity cluster: {t['actor']}\n\n"
        f"Summary:\n{t['summary']}\n\n"
        f"Associated ATT&CK for ICS tactics: {', '.join(t['ttps'])}\n\n"
        f"Indicators observed:\n" + "\n".join(f"- {i}" for i in t["indicators"]) + "\n"
    )
    with open(f"{OUT_DIR}/{t['id']}.txt", "w") as f:
        f.write(text)

with open(f"{OUT_DIR}/index.json", "w") as f:
    json.dump(TEMPLATES, f, indent=2)

print(f"Wrote {len(TEMPLATES)} synthetic advisories to {OUT_DIR}")
