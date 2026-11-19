# SIM-005 Investigation Report
Investigation Time Window: 2026/10/05 17:00:00.000 to 2026/10/05 17:30:00.000

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

---

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

---

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

## Step One: Initial Triage and HR Account Telemetry
The first thing we need to do in this scenario is identify Danielle Brooks's (`dbrooks`) account parameters, assets, and active session information. To do this, we'll run a base query that helps us inspect HR activity in chronological order:

```cql
scenario_id="EHS-SIA-SIM-006" user_name="dbrooks"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, user_name, source_ip, asset_name, target_asset_name, session_id, event_category, action, file_name, outcome])
```

### Results
* **Event IDs:** `HR-01` through `HR-14`
* **User:** `dbrooks`
* **Source IPs:**
* `203.0.113.55` (`HR-01` through `HR-13`)
* `10.20.1.41` (`HR-14`)
* **Asset Name:** `EHS-HR-WS01`
* **Target Asset Names:**
  * `null` (`HR-01`)
  * `EHS-FILE-01` (`HR-02` through `HR-13`)
  * `EHS-HR-WS01` (`HR-14`)
* **Session ID:** `s-hr-01`
* **Event Category:**
  * `authentication` (`HR-01`)
  * `file` (`HR-02` through `HR-14`)
* **Action:**
  * `login` (`HR-01`)
  * `file_read` (`HR-02` through `HR-13`)
  * `archive_create` (`HR-14`)
* **File Name:**
  * `null` (`HR-01`)
  * `training_record_01.txt` through `training_record_12.txt` (`HR-02` through `HR-13`)
  * `training_records.zip` (`HR-14`)
* **Outcome:** `success`

Looking at these results, we can immediately spot a few major red flags:
* `dbrooks` is logging in and performing `file_read` actions under an unknown, external IP address (`203.0.113.55`) for the first 13 events, before a file archive event takes place under the expected internal IP (`10.20.1.41`).
* The session (`s-hr-01`) for `dbrooks` is interacting with files hosted on `EHS-FILE-01`, which is designated in our Asset Inventory as our central file service.
* Repeatedly querying and reading a sequential list of files in a matter of 12 minutes is highly suspicious and unusual behavior for an HR employee during normal operations.
* The files accessed by `dbrooks` are named `training_record_01.txt` through `training_record_12.txt`, and the resulting archive is titled `training_records.zip`. Without further investigation, this immediately looks like data staging and preparation for exfiltration. Further investigation is required.

---

## Step Two: Deep Dive into File Access and Volume
Now that we've determined suspicious activity has occurred, we want to look even deeper into the specific file records associated with the session. We'll tighten our query scope to isolate the file read operations:

```cql
scenario_id="EHS-SIA-SIM-006" user_name="dbrooks" action="file_read"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, user_name, source_ip, asset_name, target_asset_name, session_id, file_name, file_path, action, outcome])
```

We can also run a quick aggregation query to check frequency and distribution across sessions:

```cql
scenario_id="EHS-SIA-SIM-006" user_name="dbrooks" action="file_read"
| groupBy([session_id], function=count())
| table([session_id, count])
```

While this returns a straightforward count for this specific session, it's a great pattern to verify how frequently file access events trigger under a single session token.

### Results
In total, we count 12 separate files being read sequentially by `dbrooks`, mapped to Event IDs `HR-02` through `HR-13`.

Furthermore, our index path field points us directly to the directory structure where these records reside:
* `HR/training_records/training_records_X.txt` (where `X` ranges from `01` through `12` for each respective event)

---

## Step Three: Analyzing the Archive Creation Event
Now that we've examined the file read events, it's time to take a closer look at the archive creation phase (`a-hr-01`). We pull specific parameters surrounding the archiving action using a targeted query:

```cql
scenario_id="EHS-SIA-SIM-006" user_name="dbrooks" action="archive_create"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, user_name, source_ip, asset_name, target_asset_name, session_id, archive_id, file_name, file_path, action, outcome])
```

### Results
* **Event ID:** `HR-14`
* **User:** `dbrooks`
* **Source IP:** `10.20.1.41`
* **Asset Name:** `EHS-HR-WS01`
* **Target Asset Name:** `EHS-HR-WS01`
* **Session ID:** `s-hr-01`
* **Archive ID:** `a-hr-01`
* **File Name:** `training_records.zip`
* **File Path:** `C:/Users/dbrooks/Temp/training_records.zip`
* **Action:** `archive_create`
* **Outcome:** `success`

While the source IP address shifted from an unknown external address back to the expected internal workstation IP, the session ID remained constant (`s-hr-01`) and the archive ID (`a-hr-01`) links directly back to the session lineage. Archiving sensitive training documentation into a compressed archive is alarming on its own, but placing the output within a local user `Temp` directory strongly indicates temporary staging prior to exfiltration or removal.

---

## Step Four: Complete Chronological Timeline Breakdown
To encapsulate all uncovered telemetry, we map out the full sequence of events in structured YAML format:

```yaml
2026/10/05 17:05:00.000
  - action: login
  - file_name: null
  - event_id: HR-01
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:06:00.000
  - action: file_read
  - file_name: training_record_01.txt
  - event_id: HR-02
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:07:00.000
  - action: file_read
  - file_name: training_record_02.txt
  - event_id: HR-03
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:08:00.000
  - action: file_read
  - file_name: training_record_03.txt
  - event_id: HR-04
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:09:00.000
  - action: file_read
  - file_name: training_record_04.txt
  - event_id: HR-05
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:10:00.000
  - action: file_read
  - file_name: training_record_05.txt
  - event_id: HR-06
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:11:00.000
  - action: file_read
  - file_name: training_record_06.txt
  - event_id: HR-07
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:12:00.000
  - action: file_read
  - file_name: training_record_07.txt
  - event_id: HR-08
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:13:00.000
  - action: file_read
  - file_name: training_record_08.txt
  - event_id: HR-09
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:14:00.000
  - action: file_read
  - file_name: training_record_09.txt
  - event_id: HR-10
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:15:00.000
  - action: file_read
  - file_name: training_record_10.txt
  - event_id: HR-11
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:16:00.000
  - action: file_read
  - file_name: training_record_11.txt
  - event_id: HR-12
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:17:00.000
  - action: file_read
  - file_name: training_record_12.txt
  - event_id: HR-13
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 203.0.113.55

2026/10/05 17:18:00.000
  - action: archive_create
  - file_name: training_records.zip
  - event_id: HR-14
  - session_id: s-hr-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
  - user_name: dbrooks
  - asset_name: EHS-HR-WS01
  - source_ip: 10.20.1.41
```

---

## Recommendation and Incident Triage
### Disposition Summary
* **HR Department Chain (`dbrooks` / `EHS-HR-WS01`):** **Escalate to Riley (`rmorgan`).** The sequence of events exhibits classic indicators of suspicious data staging. An HR account authenticated from an unknown external IP address, rapidly accessed a sequential batch of training records on the file service (`EHS-FILE-01`), and compiled them into a compressed zip archive within a local temporary directory under session token `s-hr-01`.

### Supporting Evidence
Danielle Brooks (`dbrooks`) is an HR employee whose workstation and session were leveraged to query and archive records in rapid succession, initiated from an unrecognized external IP address not present in our Asset Inventory:
1. **2026/10/05 17:05:00.000 (`HR-01`):** `dbrooks` logs in from an unknown external IP address (`203.0.113.55`) under session ID `s-hr-01`. No preceding failed login attempts appear in our query scope.
2. **2026/10/05 17:06:00.000 through 17:17:00.000 (`HR-02` to `HR-13`):** `dbrooks` reads `training_record_01.txt` through `training_record_12.txt` in strict sequential order, accessing a new record approximately once every minute under the same active session ID.
3. **2026/10/05 17:18:00.000 (`HR-14`):** Operating under the workstation's expected internal IP (`10.20.1.41`) while maintaining session continuity (`s-hr-01`), `dbrooks` compiles the accessed data into a local archive file (`training_records.zip`) saved in the user `Temp` directory.

### What Remains Unknown and Requires Further Scoping
While this anomalous sequence of events warrants immediate escalation, several investigative questions remain unanswered and require broader telemetry review:
* Was this activity performed by Danielle Brooks from an unrecorded alternate device or remote connection, or did an external threat actor compromise her credentials? If compromised, how were credentials obtained (e.g., credential stuffing, phishing, or session token theft)?
* If a phishing campaign was involved, did other Ellington Health Systems employees receive similar malicious emails, and did anyone else interact with attachments or links? Active Directory sign-in logs, MFA validation records, and email gateway telemetry must be audited.
* Does `training_records.zip` definitively contain all 12 accessed files, or were additional files staged, copied, or moved prior to compression? Endpoint process execution and command-line history logs should be examined for utility arguments (`tar`, `Compress-Archive`, 7-Zip, etc.).
* Was the staged archive prepared for immediate data exfiltration, or was it part of a broader destructive or ransomware staging routine? Network egress, proxy, and firewall logs must be inspected for both IP addresses (`203.0.113.55` and `10.20.1.41`) during and immediately following the investigation window to check for outbound data transfers.
* What sensitive personnel or patient-adjacent data was contained within the training files?
* Did the threat actor attempt lateral movement from `EHS-HR-WS01` or `EHS-FILE-01` to other internal systems, or attempt privilege escalation?
* Were any persistence mechanisms (such as scheduled tasks, registry run keys, or backdoors) established following the archive creation?
