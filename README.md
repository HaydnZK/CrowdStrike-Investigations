# CrowdStrike Falcon Incident Response Investigations
Welcome to my repository of structured incident response investigations. I built these labs using CrowdStrike Falcon telemetry to sharpen my threat detection, log analysis, and triage workflows. Every investigation in this repository takes place within a fictional enterprise environment called Ellington Health Systems, featuring consistent user accounts, assets, and system architectures that mirror real-world corporate networks.

---

## Environment Overview: Ellington Health Systems
To maintain consistency across all scenarios, the investigations operate within a simulated healthcare and financial infrastructure. Understanding this baseline allows for accurate behavioral analysis when anomalies occur.

### Key Personnel and Accounts
* **Jordan Blake:** Billing specialist (`jblake` / Asset: `EHS-WS-01`)
* **Maya Thompson:** Registered nurse (`mthompson` / Asset: `EHS-WS-02`)
* **Arjun Mehta:** Medical assistant (`amehta` / Asset: `EHS-CLIN-WS02`)
* **Elena Martinez:** Clinic supervisor (`emartinez` / Asset: `EHS-CLIN-WS02`)
* **Danielle Brooks:** HR specialist (`dbrooks` / Asset: `EHS-HR-WS01`)
* **Charles Bennett:** Chief financial officer (`cbennett` / Asset: `EHS-EXEC-WS01`)
* **Alex Carter:** Systems administrator (`acarter` / Asset: `EHS-IT-WS01`)
* **Amara Okafor:** Helpdesk specialist (`aokafor` / Asset: `EHS-IT-WS01`)
* **Dr. Aaron Patel:** Physician (`apatel` / Asset: `EHS-WS-02`)
* **Riley Morgan:** SOC escalation contact (`rmorgan` / Escalation contact)

### Core Business Infrastructure
* **EHS-WEB-01 (`10.20.0.21`):** Application portal
* **EHS-APP-01 (`10.20.0.22`):** Business applications
* **EHS-FILE-01 (`10.20.0.23`):** Department file shares

---

## Investigation Index
This repository is organized into distinct simulation modules, each tackling a different pillar of security operations, from initial access triage to endpoint forensics and detection engineering.

### 1. SIM-001: Finding Security Events in Jordan's Billing Activity
* **Objective:** Investigate a suspicious sequence of authentication events on the billing platform.
* **Key Findings:** Discovered an external brute-force attack from an unknown public IP address targeting Jordan Blake's account while concurrent internal logins occurred.
* **Outcome:** Confirmed account compromise, established proper investigative scoping, and escalated the incident.

### 2. SIM-003: Normal Administration and Unusual Executive Access
* **Objective:** Differentiate between routine administrative support tickets and unauthorized executive access.
* **Key Findings:** Analyzed helpdesk administration actions alongside executive application access on CFO Charles Bennett's asset to establish a valid operational baseline.
* **Outcome:** Confirmed authorized change management activity and ruled out malicious lateral movement.

### 3. SIM-004: Clinical Document and Process Investigation
* **Objective:** Trace a multi-stage compromise starting from an email attachment delivered to a clinical employee.
* **Key Findings:** Followed mail, process, file, and network telemetry to reconstruct the complete attack chain on a clinical workstation.
* **Outcome:** Built a comprehensive endpoint timeline detailing malicious payload execution and network callback behavior.

### 4. SIM-005: From Billing Activity to a Detection
* **Objective:** Bridge raw log analysis with detection engineering by evaluating a supplied training detection against a billing case.
* **Key Findings:** Mapped specific authentication events to rule logic while comparing anomalous behavior against authorized IT activity.
* **Outcome:** Validated detection rule accuracy and minimized false positive rates for future alerting.

### 5. SIM-006: Document and Escalate a File-Access Incident
* **Objective:** Investigate sensitive HR file access requiring a formal escalation record.
* **Key Findings:** Evaluated user sessions, target assets, and specific file activity associated with Danielle Brooks' HR environment.
* **Outcome:** Compiled structured handoff documentation and delivered precise evidence to the SOC escalation contact.

---

## Skills and Methodologies Demonstrated
* **Telemetry Analysis:** Querying and parsing raw logs using CrowdStrike Query Language (CQL).
* **Behavioral Baselining:** Contrasting anomalous user behavior against peer activity to eliminate false positives.
* **Incident Triage:** Distinguishing between credential brute-forcing, authorized administrative actions, and endpoint compromise.
* **Documentation:** Crafting clear, reproducible incident reports and handoff notes ready for Tier 2 escalation or SOC review.
