# SIM-004 Investigation Report
Investigation Time Window: 2026/10/04 16:00:00.000 to 2026/10/04 16:20:00.000

## Environment Overview: Ellington Health Systems
### Accounts and expected clients

| Account | Department | Asset | Expected client |
| --- | --- | --- | --- |
| jblake | Billing | EHS-WS-01 | 10.20.1.21 |
| mthompson | Clinical | EHS-WS-02 | 10.20.1.31 |
| amehta | Clinical | EHS-CLIN-WS02 | 10.20.1.32 |
| emartinez | Clinical | EHS-CLIN-WS02 | 10.20.1.22 |
| dbrooks | HR | EHS-HR-WS01 | 10.20.1.41 |
| cbennett | Finance | EHS-EXEC-WS01 | 10.20.1.51 |
| acarter | IT | EHS-IT-WS01 | 10.20.1.61 |
| aokafor | IT | EHS-IT-WS01 | 10.20.1.23 |
| apatel | Clinical | EHS-WS-02 | 10.20.1.33 |

### Asset inventory

| Asset | Address | Role |
| --- | --- | --- |
| EHS-WS-01 | 10.20.0.11 | Windows billing |
| EHS-WS-02 | 10.20.0.12 | Windows clinical |
| EHS-CLIN-WS02 | 10.20.0.13 | Windows clinical |
| EHS-HR-WS01 | 10.20.0.14 | Windows HR |
| EHS-EXEC-WS01 | 10.20.0.15 | Windows executive |
| EHS-IT-WS01 | 10.20.0.16 | Windows IT |
| EHS-WEB-01 | 10.20.0.21 | Linux web service |
| EHS-APP-01 | 10.20.0.22 | Linux application service |
| EHS-FILE-01 | 10.20.0.23 | File service |
| EHS-LOG-01 | 10.20.0.24 | Logical logging utility |

### Approved changes

| Reference | Authorized account | Activity |
| --- | --- | --- |
| CHG-EHS-014 | aokafor | Helpdesk maintenance |
| CHG-EHS-015 | acarter | Inventory task |
| CHG-EHS-016 | acarter | Inventory task |
| CHG-EHS-017 | acarter | Internal backup |
| CHG-EHS-N00 | Assigned workflow user | Approved synthetic application inventory |
| CHG-EHS-N01 | Assigned workflow user | Approved synthetic application inventory |
| CHG-EHS-N02 | Assigned workflow user | Approved synthetic application inventory |
| CHG-EHS-N03 | Assigned workflow user | Approved synthetic application inventory |
| CHG-EHS-N04 | Assigned workflow user | Approved synthetic application inventory |
| CHG-EHS-N05 | Assigned workflow user | Approved synthetic application inventory |
| CHG-EHS-N06 | Assigned workflow user | Approved synthetic application inventory |
| CHG-EHS-N07 | Assigned workflow user | Approved synthetic application inventory |

---

## Step One: Initial Triage and Detection Rule Verification
The first step in this scenario is checking for a trigger on our detection rules and pulling base telemetry to establish our investigation anchor. To do this, we run a base query filtering for the detection category and structuring the results into a clean table for initial review:

```cql
scenario_id="EHS-SIA-SIM-005" event_category="detection"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, detection_id, training_severity, user_name, asset_name, source_ip, session_id, related_event_ids, action, outcome])

```

Executing this query gives us our primary lead:
* **Detection ID:** `DET-BI-01`
* **Event ID:** `BI-04`
* **Severity:** High
* **User:** `jblake` (Jordan)
* **Source IP:** `10.20.1.21`
* **Asset Name:** `EHS-WS-01` (Windows Billing Workstation)
* **Related Event IDs:** `BI-02`, `BI-03`

This initial detection immediately points us toward a high-severity event originating from Jordan Blake's billing workstation, backed up by related telemetry events that we need to unpack.

---

## Step Two: Validating Relevant Events and Download Artifacts
Now that we've confirmed our detection rule fired on `EHS-WS-01`, we need to validate the supporting events and reconstruct the exact sequence of actions that took place during our investigation window. We run a targeted query focusing on user `jblake` with expanded process and file parameters:

```cql
scenario_id="EHS-SIA-SIM-005" user_name="jblake"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, event_category, user_name, asset_name, source_ip, session_id, process_id, parent_process_id, process_name, destination_ip, destination_port, action, outcome, file_name])
```

Reviewing the query output reveals a clear, highly suspicious timeline:
1. **16:01:00.000 (`BL-00`):** `jblake` logs into his workstation (`EHS-WS-01`) via his expected client IP (`10.20.1.21`). This initial login appears benign.
2. **16:02:00.000 (`BL-01`):** `jblake` downloads a file named `invoice_review.ps1` from an external, unverified source domain: `invoice-review.example`.
3. **16:02:50.000 (`BI-00P`):** `Explorer.exe` spawns on Jordan's station (`PID: p-bi-200`, `PPID: null`) directly following the file download.
4. **16:03:00.000 (`BI-02`):** The downloaded script initiates PowerShell (`process_name: powershell.exe`, `PID: p-bi-201`, `PPID: p-bi-200`).
5. **16:03:05.000 (`BI-03`):** Jordan's workstation initiates an outbound network connection to an unknown external public IP address (`203.0.113.80`) over port `443` (`PID: p-bi-201`, `PPID: null`).
6. **16:04:00.000 (`BI-04`):** Our initial detection rule for this suspicious execution sequence fires.

While PowerShell execution spawned from `Explorer.exe` isn't anomalous on its own in every context, the tight correlation of downloading an unknown script from an external domain, immediate execution, and rapid outbound beaconing to an unrecognized external IP on a dedicated billing workstation sets off major red flags.

---

## Step Three: Comparative Baselining Against Approved Changes (acarter vs. jblake)
Before making an escalation decision, we need to compare Jordan's activity against normal operational baselines and authorized change records in our environment. Specifically, we want to examine Alex Carter's (`acarter`) IT inventory activities to understand how authorized administrative tasks manifest in our logs. We run a query filtering for `acarter`:

```cql
scenario_id="EHS-SIA-SIM-005" user_name="acarter"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, user_name, asset_name, source_ip, session_id, process_name, action, outcome, change_reference])
```

This query highlights two key events for the IT department:
1. **16:05:30.000 (`BI-05A`):** `acarter` logs into `EHS-IT-WS01` from source IP `10.20.1.61` (`session_id: s-bi-it`, `action: login`, `outcome: success`, `change_reference: none`).
2. **16:06:00.000 (`BI-05`):** `acarter` executes `powershell.exe` on `EHS-IT-WS01` (`action: process_start`, `outcome: success`, `change_reference: CHG-EHS-015`).

When we cross-reference this with our Approved Changes register, we find:
* **Reference:** `CHG-EHS-015`
* **Authorized Account:** `acarter`
* **Activity:** Inventory task
* **Asset / Expected Client:** `EHS-IT-WS01` / `10.20.1.61`

This comparison provides vital context. Alex Carter is an authorized IT user performing scheduled inventory tasks on an IT workstation (`EHS-IT-WS01`) backed by a valid change ticket (`CHG-EHS-015`), making PowerShell execution entirely expected and benign in that scope. Conversely, Jordan Blake (`jblake`) is working out of the Billing department on `EHS-WS-01`, has zero approved change tickets, and executed an unverified downloaded script (`invoice_review.ps1`) connecting out to an unknown external IP.

---

## Step Four: Final Chronological Timeline Breakdown
To encapsulate all uncovered telemetry and process relationships, here is the complete chronological breakdown of the billing workstation incident in structured YAML format:

```yaml
2026/10/04 16:01:00.000
  - action: login
  - file_name: null
  - event_id: BL-00
  - session_id: s-bi-billing
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: jblake
  - asset_name: EHS-WS-01

2026/10/04 16:02:00.000
  - action: file_download
  - file_name: invoice_review.ps1
  - event_id: BL-01
  - session_id: s-bi-billing
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: invoice-review.example
  - user_name: jblake
  - asset_name: EHS-WS-01

2026/10/04 16:02:50.000
  - action: process_start
  - file_name: null
  - event_id: BI-00P
  - session_id: s-bi-billing
  - process_name: Explorer.exe
  - process_id: p-bi-200
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: jblake
  - asset_name: EHS-WS-01

2026/10/04 16:03:00.000
  - action: process_start
  - file_name: invoice_review.ps1
  - event_id: BI-02
  - session_id: s-bi-billing
  - process_name: powershell.exe
  - process_id: p-bi-201
  - parent_process_id: p-bi-200
  - destination_ip: null
  - source_domain: null
  - user_name: jblake
  - asset_name: EHS-WS-01

2026/10/04 16:03:05.000
  - action: connection
  - file_name: null
  - event_id: BI-03
  - session_id: s-bi-billing
  - process_name: powershell.exe
  - process_id: p-bi-201
  - parent_process_id: null
  - destination_ip: 203.0.113.80
  - source_domain: null
  - user_name: jblake
  - asset_name: EHS-WS-01

2026/10/04 16:04:00.000
  - action: detection
  - file_name: null
  - event_id: BI-04
  - session_id: s-bi-billing
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: jblake
  - asset_name: EHS-WS-01
```

---

## Recommendation and Incident Triage
### Disposition Summary
* **Billing Workstation Chain (`jblake` / `EHS-WS-01`):** **Escalate.** The chain of events exhibits clear indicators of unauthorized script execution, anomalous PowerShell activity on a billing endpoint, and unverified outbound communication with an external IP address with zero supporting change management records.
* **IT Inventory Chain (`acarter` / `EHS-IT-WS01`):** **Close as Benign.** All telemetry maps cleanly to approved IT change ticket `CHG-EHS-015` and expected administrative responsibilities.

### What Remains Unknown and Requires Further Scoping
While our telemetry confirms suspicious execution, we must avoid overclaiming unverified impacts. Further investigation should focus on answering the following unknowns:
* What happened prior to these events? Did Jordan initiate this browsing session independently, or was there prior compromise or session hijacking?
* What were the exact contents and payload of the downloaded file (`invoice_review.ps1`)?
* What specific PowerShell command-line arguments and script blocks were executed by PID `p-bi-201`?
* Who owns the external destination IP address (`203.0.113.80`), and is `invoice-review.example` linked to known threat actor infrastructure?
* Was data exfiltrated over port 443 during the outbound connection, or was the channel used to drop a secondary payload?
* Did the attacker achieve lateral movement to other workstations or access sensitive billing databases across Ellington Health Systems following this execution?
