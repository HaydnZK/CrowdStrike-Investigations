# SIM-003 Investigation Report
Investigation Time Window: 2026/10/03 15:00:00.000 to 2026/10/03 15:20:00.000

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

## Step One: Initial Triage
The first step in this scenario is to get an overview of Maya's (mthompson) activity in the time period provided. For this, we do a simple query that isolates all of Maya's events within the time period along with some relevant information (the timestamp, event id, username, asset name, source IP, session ID, event category, action, and outcome) and put them all into a clean table for ease:

```cql
scenario_id="EHS-SIA-SIM-004" user_name="mthompson"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, user_name, asset_name, source_ip, session_id, event_category, action, outcome])
```

Once we do this, we get a clean table that shows us a timeline that ranges from 15:01:00.000 to 15:04:20.000. Following the event category and action, we can see Maya login, receive mail, start a process twice, perform a network connection, and start writing to a file. This sequence of events is definitely a red flag, but does not immediately tell us the full story.

At first glance, it would appear that Maya received a possible phishing email, opened the file within it, and the file beaconed out to get instructions, resulting in a potentially malicious file being opened. The next step is to investigate this further.

---

## Step Two: Investigating Initial Access and Mail Artifacts
Now that we have found the potentially malicious sequence of events, the next step is to investigate it further. We keep the same time range from before, and simply add in a couple new values to the table to get some more information (file_name, message_id, and source_domain):

```cql
scenario_id="EHS-SIA-SIM-004" user_name="mthompson"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, user_name, asset_name, source_ip, session_id, event_category, source_domain, action, outcome, file_name, message_id, process_id])
```

Adding these new fields to the table, we can see a much clearer picture of what is happening. Maya logs into her computer and receives an email from the source domain clinic-schedule.example with the file clinic_schedule.docx with a message ID of M-CL-01, and she proceeds to open this file. Upon opening this file, a new process starts and forms a network connection, before a new file gets written (clinic_update.ps1). We can note that there are no updates or changes approved for mthompson workstation in the approved changes register.

### Message ID and Relevant Info
* 2026/10/03 15:02:00.000 - event_id:CL-01 - session_id:s-cl-01 - source_domain:clinic-schedule.example - action:mail_received - file_name:clinic_schedule.docx - message_id:M-CL-01
* 2026/10/03 15:04:00.000 - event_id:CL-02 - session_id:s-cl-01 - action:process_start - file_name:clinic_schedule.docx - message_id:M-CL-01 - process_id:p-cl-100

---

## Step Three: Process Lineage and Execution Tree Analysis
Now that we are starting to see more red flags popping up from our more generic triaging, we are going to close the scope in and build a parent-to-child process relationship. To do this, we are going to zero in on the process events and look at some relevant fields to get more information, as a shared account and nearby timestamps are not enough on their own. We do this with the query:

```cql
scenario_id="EHS-SIA-SIM-004" user_name="mthompson" event_category="process"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, user_name, asset_name, source_ip, session_id, process_id, parent_process_id, process_name, message_id, file_name, action, outcome])
```

This query shows us a table of relevant information for the two process_start events and immediately more red flags appear. In the initial event, we can see that the clinic_schedule.docx file starts the WINWORD.EXE process and 10 seconds later, begins the powershell.exe process. WINWORD.EXE process carries a process_id of p-cl-100 and a parent_process_id of null, while the powershell.exe process has a process_id of p-cl-101 and a parent_process_id of p-cl-100. This tells us that the powershell.exe process did start as a result of the file being opened prior.

The next thing we want to do is run a selected-field process query, which we will do with a new query that uses the select command within the query to change which columns are returned. The query used looks like this:

```cql
scenario_id="EHS-SIA-SIM-004" user_name="mthompson" event_category="process"
| sort(field=@timestamp, order=asc, limit=2000)
| select([event_id, @timestamp, user_name, asset_name, session_id, process_id, parent_process_id, process_name])
```

This gives us a similar table view for the events. Using select and table can yield similar results, but select is generally used for large exports and pipelines because it does not buffer or cap results. Table is used for a quick visual inspection and dashboards, because it automatically sorts results and has a hard limit of 200. We now isolate:

### Parent Process IDs
* 2026/10/03 15:04:00.000 - session_id:s-cl-01 - process_id:p-cl-100 - parent_process_id:null - process_name:WINWORD.EXE - message_id:M-CL-01

### Child Process IDs
* 2026/10/03 15:04:10.000 - session_id:s-cl-01 - process_id:p-cl-101 - parent_process_id:p-cl-100 - process_name:powershell.exe - message_id:null

---

## Step Four: Network Activity and Final Chronological Timeline
Now that we have discovered the relevant file that initiated these events, as well as what the parent-to-child relationships are for the process events, we need to look a little more into the network event we saw earlier. To start, we are going to look into the child process network activity:

```cql
scenario_id="EHS-SIA-SIM-004" user_name="mthompson" event_category="network"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, user_name, asset_name, source_ip, session_id, process_id, destination_ip, destination_port, action, outcome])
```

Upon using this search, we can see that the process_id from before (p-cl-101) that was tied to the powershell process is initiating a connection to an unknown public IP address (198.51.100.20) via port 443. After we do this, it is time to take another look at our full timeline of events alongside a few new fields that we added from our investigation:

```cql
scenario_id="EHS-SIA-SIM-004" user_name="mthompson"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, event_category, source_ip, action, outcome, asset_name, session_id, process_id, process_name, parent_process_id, file_name, destination_ip, destination_port, source_domain])
```

With this full picture and all of our uncovered information, we can compile all of our relevant fields and IDs and make our recommendation for whether this is benign, needs more information, or should be escalated.

### Relevant IDs in UTC Order

```yaml
2026/10/03 15:01:00.000
  - action: login
  - file_name: null
  - event_id: CL-00
  - session_id: s-cl-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null

2026/10/03 15:02:00.000
  - action: mail_received
  - file_name: clinic_schedule.docx
  - event_id: CL-01
  - session_id: s-cl-01
  - process_name: null
  - process_id: null
  - parent_process_id: null
  - destination_ip: null
  - source_domain: clinic-schedule.example

2026/10/03 15:04:00.000
  - action: process_start
  - file_name: clinic_schedule.docx
  - event_id: CL-02
  - session_id: s-cl-01
  - process_name: WINWORD.EXE
  - process_id: p-cl-100
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null

2026/10/03 15:04:10.000
  - action: process_start
  - file_name: null
  - event_id: CL-03
  - session_id: s-cl-01
  - process_name: powershell.exe
  - process_id: p-cl-101
  - parent_process_id: p-cl-100
  - destination_ip: null
  - source_domain: null

2026/10/03 15:04:15.000
  - action: connection
  - file_name: null
  - event_id: CL-04
  - session_id: s-cl-01
  - process_name: null
  - process_id: p-cl-101
  - parent_process_id: null
  - destination_ip: 198.51.100.20
  - source_domain: null

2026/10/03 15:04:20.000
  - action: file_write
  - file_name: clinic_update.ps1
  - event_id: CL-05
  - session_id: s-cl-01
  - process_name: null
  - process_id: p-cl-101
  - parent_process_id: null
  - destination_ip: null
  - source_domain: null
```

---

## Recommendation and Incident Triage
My recommendation is to **escalate** the alert due to the clear multi-stage attack chain:
1. mthompson logged into workstation EHS-WS-02.
2. mthompson received an email with an attachment named `clinic_schedule.docx` from `clinic-schedule.example`.
3. mthompson opened the attachment through WINWORD.EXE (process_id `p-cl-100`).
4. The Word process spawned PowerShell (process_id `p-cl-101`, parent `p-cl-100`).
5. PowerShell initiated an outbound network connection to an unknown external public IP address (`198.51.100.20`) via port `443`.
6. Immediately following this connection, a new script file named `clinic_update.ps1` was written to disk on mthompson system.

### What Remains Unknown and Requires Further Scoping
* What was inside the received document (`clinic_schedule.docx`)
* What was inside the created script (`clinic_update.ps1`)
* What specific commands were issued via the outbound connection
* What the ultimate goal of the attack is
* If there were other users who received this email across the environment
* If the attacker attempted lateral movement to other devices from here
* If additional payloads were downloaded afterwards (ransomware, spyware, coinminers, etc.)
* If the attacker was able to access or exfiltrate sensitive data

