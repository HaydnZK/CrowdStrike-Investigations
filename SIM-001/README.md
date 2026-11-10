# Incident Investigation Report: Credential Brute-Force and Account Compromise

## Summary
This project walks through a practical telemetry investigation using CrowdStrike Falcon data to triage an active credential brute-force attack and subsequent account compromise. Working through a simulated corporate scenario, I analyzed suspicious authentication patterns on a user account where an external public IP address hammered the system with failed logins before successfully gaining access. By cross-referencing that external traffic against concurrent internal logins from the user's expected private IP and comparing it to a peer baseline, I ruled out routine user error, confirmed the compromise, and escalated the case for deeper post-authentication scoping. It serves as a solid example of how to dissect authentication logs, write effective queries, and build a clear investigative narrative for the SOC.

---

## Investigation Overview
* **Scenario ID:** EHS-SIA-SIM-001
* **Investigation Window:** October 1, 2026, from 14:00 to 14:15 UTC
* **Target Application:** ehs_billing
* **Target Asset:** EHS-WS-01
* **Analyst Disposition:** Escalate
* **Final Conclusion:** Confirmed Account Compromise

---

## Executive Summary
This simulation exercise focuses on investigating authentication anomalies within a corporate environment using CrowdStrike Falcon telemetry. By analyzing concurrent login streams for two distinct user accounts (jblake and mthompson) during a strict fifteen-minute window, the investigation successfully identified a targeted credential brute-force attack from an unknown public IP address. The attack resulted in a confirmed account compromise, successfully distinguishing malicious external intervention from routine internal user error.

---

## Phase 1: Scoping and Initial Telemetry Filtering
The investigation began by scoping the telemetry down to the specific simulation parameters using basic log filtering. 

```cql
scenario_id="EHS-SIA-SIM-001"
```

This initial filter isolated fourteen total events relevant to the training scenario. From here, the focus shifted to the primary subject of interest, Jordan Blake (jblake), to examine his authentication history within the defined timeframe.

---

## Phase 2: Analyzing Subject Telemetry (Jordan Blake)
To evaluate Jordan's login pattern, the telemetry was sorted chronologically.

```cql
scenario_id="EHS-SIA-SIM-001" user_id="jblake"
| sort(field=@timestamp, order=asc, limit=2000)
```

This query reduced the dataset to eight authentication events containing a mix of successes and failures across two distinct IP addresses. According to human resources and asset inventory records, Jordan's assigned private corporate IP address is 10.20.1.21. However, the logs revealed a series of failed authentication attempts originating from an unlisted public IP address (192.0.2.44), culminating in a successful login from that same external address.

To obtain a clearer quantitative breakdown of the activity, a grouped aggregation query was executed.

```cql
scenario_id="EHS-SIA-SIM-001" source_type="authentication" user_id="jblake"
| groupBy([user_id, src_ip, outcome], function=count())
```

### Key Telemetry Findings for Jordan Blake:
* **Expected Private IP (10.20.1.21):** Two successful login events, corresponding with active page navigation and re-authentication during the fifteen-minute window.
* **Unexpected Public IP (192.0.2.44):** Five failed login attempts followed by one successful login attempt.

---

## Phase 3: Establishing a Behavioral Baseline (Maya Thompson)
To ensure the anomalies identified on Jordan's account were not simply standard network behavior or environment-wide authentication quirks, analyst baselining was performed on a peer account, Maya Thompson (mthompson).

```cql
scenario_id="EHS-SIA-SIM-001" user_id="mthompson"
| sort(field=@timestamp, order=asc, limit=2000)
```

Maya's telemetry showed three total login events within the window. Two failed attempts due to invalid passwords preceded a successful login. Crucially, all three events originated entirely from her assigned corporate private IP address (10.20.1.31).

This comparison highlighted a stark operational difference: Maya exhibited classic user error patterns consisting of minor password typos from an expected internal location, whereas Jordan experienced a multi-attempt brute-force sequence from an external public source.

---

## Phase 4: Incident Analysis and Conclusion
### Supporting Evidence and Logic
The presence of five failed login attempts from an unknown public IP address (192.0.2.44) points directly toward a credential brute-force or password-spraying technique.

Crucially, simultaneous telemetry proved that Jordan was actively interacting with resources from his corporate-assigned private IP address (10.20.1.21) during that exact same fifteen-minute window. This concurrent internal activity definitively ruled out the possibility that Jordan was simply traveling or connecting from an external network device. An attacker successfully guessed the credentials from the outside while the legitimate user sat at their workstation.

### Questions Answered During Triage
* **Which source IP requires investigation?** 192.0.2.44
* **How many failed logins came from that source?** Five (evt-000001 through evt-000005)
* **Which event recorded the successful external login?** login_attempt (evt-000006)
* **Disposition:** Escalate
* **Supported Conclusion:** Confirmed Account Compromise

---

## Phase 5: Post-Incident Handoff and Scope Determination
Because an external entity successfully authenticated into Jordan's account following a brute-force sequence, the incident was escalated to Tier 2 incident response.

### Analyst Notes and Pinned Evidence
I pinned all events that originated from the unknown public IP address. This includes the five failed login attempts as well as the single successful login attempt. These events happen alongside several successful login attempts originating from the expected private IP address. These all happened on Oct. 1, 2026 between 14:00:00.000 UTC and 14:15:00.000 UTC.

### Identified Unknowns and Next Steps
While the initial root cause was successfully identified as an unauthorized external login, further investigation is required to determine the full scope of the breach. Outstanding investigative objectives include:
* Determining whether the attacker accessed any other corporate accounts or sensitive assets beyond ehs_billing.
* Checking for post-authentication commands, lateral movement, or session persistence mechanisms.
* Verifying whether any malware was deployed or if data exfiltration occurred during the active session window.

---

## Final Takeaways
Investigations like this highlight why methodical log analysis and behavioral baselining are core pillars of blue-team operations. Spotting an anomaly requires more than just noting a failed login; it demands contextualizing the activity against peer baselines and concurrent internal sessions to separate legitimate user error from sophisticated external attacks.

Demonstrating practical, hands-on experience with SIEM telemetry, threat detection logic, and structured incident triage builds a strong foundation for SOC analyst and MDR roles. Showcasing these measurable outcomes and clear investigative workflows helps bridge the gap between technical practice and real-world security value.

---

## Appendix: Search Queries Used
1. **Full chronological sort of target login events:**
```cql
scenario_id="EHS-SIA-SIM-001" user_id="jblake"
| sort(field=@timestamp, order=asc, limit=2000)
```

2. **Grouped authentication count by source IP and outcome:**
```cql
scenario_id="EHS-SIA-SIM-001" source_type="authentication" user_id="jblake"
| groupBy([user_id, src_ip, outcome], function=count())
```

3. **Baseline peer comparison query:**
```cql
scenario_id="EHS-SIA-SIM-001" user_id="mthompson"
| sort(field=@timestamp, order=asc, limit=2000)
```
