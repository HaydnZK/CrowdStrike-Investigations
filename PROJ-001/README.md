# EHS-SIA-PROJ-001 Investigation Triage Report
**Investigation Time Window:** `2026/10/06 14:00:00.000` to `2026/10/06 14:30:00.000`

This is my first completely unguided investigation within the cyber range, where I crafted my own queries and workflow armed with only the `scenario_id` and time range to work with. Below is the detailed triage report analyzing the anomalous activity detected on billing workstation `EHS-WS-01`.

---

## Environment Overview: Ellington Health Systems
### Accounts and Expected Clients

| Account | Department | Asset | Expected Client |
| --- | --- | --- | --- |
| jblake | Billing | `EHS-WS-01` | `10.20.1.21` |
| mthompson | Clinical | `EHS-WS-02` | `10.20.1.31` |
| amehta | Clinical | `EHS-CLIN-WS02` | `10.20.1.32` |
| emartinez | Clinical | `EHS-CLIN-WS02` | `10.20.1.22` |
| dbrooks | HR | `EHS-HR-WS01` | `10.20.1.41` |
| cbennett | Finance | `EHS-EXEC-WS01` | `10.20.1.51` |
| acarter | IT | `EHS-IT-WS01` | `10.20.1.61` |
| aokafor | IT | `EHS-IT-WS01` | `10.20.1.23` |
| apatel | Clinical | `EHS-WS-02` | `10.20.1.33` |

### Asset Inventory

| Asset | Address | Role |
| --- | --- | --- |
| `EHS-WS-01` | `10.20.0.11` | Windows billing |
| `EHS-WS-02` | `10.20.0.12` | Windows clinical |
| `EHS-CLIN-WS02` | `10.20.0.13` | Windows clinical |
| `EHS-HR-WS01` | `10.20.0.14` | Windows HR |
| `EHS-EXEC-WS01` | `10.20.0.15` | Windows executive |
| `EHS-IT-WS01` | `10.20.0.16` | Windows IT |
| `EHS-WEB-01` | `10.20.0.21` | Linux web service |
| `EHS-APP-01` | `10.20.0.22` | Linux application service |
| `EHS-FILE-01` | `10.20.0.23` | File service |
| `EHS-LOG-01` | `10.20.0.24` | Logical logging utility |

### Approved Changes

| Reference | Authorized Account | Activity |
| --- | --- | --- |
| `CHG-EHS-014` | aokafor | Helpdesk maintenance |
| `CHG-EHS-015` | acarter | Inventory task |
| `CHG-EHS-016` | acarter | Inventory task |
| `CHG-EHS-017` | acarter | Internal backup |
| `CHG-EHS-N00` through `CHG-EHS-N07` | Assigned workflow user | Approved synthetic application inventory |

---

## Phase 1: Initial Scope & Bird's-Eye View
Once we have the target time, the first thing we want to do is get an overall picture and scope of what we are dealing with. To do this, we use the query below to get a look at some relevant fields that can help narrow down where the initial alert lies:

```cql
scenario_id="EHS-SIA-PROJ-001"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, detection_id, training_severity, event_id, session_id, user_name, file_name, process_id, parent_process_id, source_ip, asset_name, action, outcome])
```

### Results
Immediately off the bat, we can see a chain of events that raises some red flags for `jblake`, as well as a couple benign-looking events for `acarter`.

#### **`jblake`**
When we look at `jblake`'s series of events in this time period, before going into depth, we can see an alarming sequence:
1. `jblake` logs in.
2. `jblake` proceeds to download a file (`payment_check.ps1`).
3. `jblake` proceeds to start a process after downloading the file. This happens less than a minute after downloading and has a PID of `p-pb-300`.
4. We see another process start event that takes place about 10 seconds after the initial process. This has a PPID of `p-pb-300` and a PID of `p-pb-301`.
5. Five seconds after the second process event, with the same PID (`p-pb-301`), we can see that there's a PowerShell script being written on `jblake`'s workstation (`payment_cache.ps1`).
6. The last visible event for `jblake` shows that the workstation initiates a network connection with the same PID (`p-pb-301`).

A few more things worth noting from this series of events:
* There are no failed login attempts prior to the successful login.
* The login occurred from `jblake`'s company-associated IP address (`10.20.1.21`).
* `jblake` works on a billing workstation, and there are no approved changes associated with his account or workstation. There's no documented reason for a PowerShell script to be run on his workstation.
* There's no associated detection ID being triggered from this activity.
* There's no severity level associated with this activity.
* We can't yet see the command-line arguments.
* We don't know what is in either of the PowerShell scripts.
* We can't see the IP address that the connection called out to.

| Time | Detection ID | Severity | Event ID | Session ID | User | File Name | PID | PPID | Source IP | Asset Name | Action | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `10-06-2026 14:06:00.000` | `null` | `null` | `PB-00` | `s-pb-01` | jblake | `null` | `null` | `null` | `10.20.1.21` | `EHS-WS-01` | login | success |
| `10-06-2026 14:07:00.000` | `null` | `null` | `PB-01` | `s-pb-01` | jblake | `payment_check.ps1` | `null` | `null` | `10.20.1.21` | `EHS-WS-01` | file_download | success |
| `10-06-2026 14:07:50.000` | `null` | `null` | `PB-00P` | `s-pb-01` | jblake | `null` | `p-pb-300` | `null` | `10.20.1.21` | `EHS-WS-01` | process_start | success |
| `10-06-2026 14:08:00.000` | `null` | `null` | `PB-02` | `s-pb-01` | jblake | `null` | `p-pb-301` | `p-pb-300` | `10.20.1.21` | `EHS-WS-01` | process_start | success |
| `10-06-2026 14:08:05.000` | `null` | `null` | `PB-03` | `s-pb-01` | jblake | `payment_cache.ps1` | `p-pb-301` | `null` | `10.20.1.21` | `EHS-WS-01` | file_write | success |
| `10-06-2026 14:08:10.000` | `null` | `null` | `PB-04` | `s-pb-01` | jblake | `null` | `p-pb-301` | `null` | `10.20.1.21` | `EHS-WS-01` | connection | success |

#### **`acarter`**
Looking at `acarter`'s activity, we can see two events:
1. `acarter` logs in.
2. A process starts on `acarter`'s workstation with a PID of `p-pb-it`.

Items worth noting:
* We don't know what the process is for `acarter`.
* `acarter` has approved changes in the documentation (two inventory tasks and one internal backup).
* The PID (`p-pb-it`) tells us this is likely associated with their scheduled approved changes.
* `acarter` logs in through their company-associated IP (`10.20.1.61`).

Based on the information, it appears that this is likely benign activity, but we'll confirm that with future queries.

| Time | Detection ID | Severity | Event ID | Session ID | User | File Name | PID | PPID | Source IP | Asset Name | Action | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `10-06-2026 14:09:30.000` | `null` | `null` | `PB-05A` | `s-pb-it` | acarter | `null` | `null` | `null` | `10.20.1.61` | `EHS-IT-WS01` | login | success |
| `10-06-2026 14:10:00.000` | `null` | `null` | `PB-05` | `s-pb-it` | acarter | `null` | `p-pb-it` | `null` | `10.20.1.61` | `EHS-IT-WS01` | process_start | success |

---

## Phase 2: Ruling Out Benign IT Activity
Now that we have our initial bird's-eye view, we want to take a closer look at a few of the items and rule out `acarter`'s activity. First up, we remove a couple of the null and redundant fields (`detection_id`, `training_severity`, and `outcome`) and add relevant fields (`change_reference`, `process_name`, `command_line`).

```cql
scenario_id="EHS-SIA-PROJ-001" user_name="acarter"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, session_id, user_name, file_name, process_id, parent_process_id, source_ip, asset_name, action, change_reference, process_name, command_line])
```

### Results
Immediately, we can look at this new information and write it off as benign. We can see:
* The Change Reference correlates to an approved inventory task (`CHG-EHS-016`) in the documentation.
* The Process Name is PowerShell, and with the addition of the command-line argument, we can see that it is listed as `powershell.exe [approved synthetic inventory]`.

With this information, we can officially zero our search in on `jblake`.

---

## Phase 3: Inspecting File Activity and Origin
Now that we have ruled out `acarter`'s activity, we take a closer look at `jblake`'s file activity:

```cql
scenario_id="EHS-SIA-PROJ-001" user_name="jblake"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, session_id, file_name, process_id, parent_process_id, asset_name, action, change_reference, process_name, command_line, source_domain])
```

### Results
With this query, we can immediately note a few things:
* There's no Change Reference associated with any of this activity. We already knew this was not listed in the documentation, but now we can definitively rule out undocumented approved changes.
* The initial process that starts after downloading the first file (`payment_check.ps1`) is `explorer.exe`. While this isn't abnormal on its own, we can see that the immediately following process is associated with PowerShell.
* The command line shows that this is a payment checker script, though there's no official payment checker script registered.
* The source domain that the script was downloaded from is `payment-check.example`. This domain isn't associated with EHS in any capacity and is immediately a red flag.

---

## Phase 4: Network and Connection Analysis
Now that we have determined the script was downloaded from an unassociated domain, claims to be a synthetic payment checker, has no associated change reference, and immediately started a PowerShell process after being downloaded, the next order of business is taking a closer look at the network activity:

```cql
scenario_id="EHS-SIA-PROJ-001" user_name="jblake"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, session_id, file_name, process_id, parent_process_id, asset_name, action, process_name, destination_ip, destination_port, target_asset_name, source_domain])
```

### Results
Unfortunately, when we add this extra information, we can't see the IP or port associated with the source domain (`payment-check.example`). However, we can see some other important details:
* The Destination IP address is `203.0.113.81`. This IP address has no association with EHS.
* The Destination Port is `443`, which means that the traffic will inherently be encrypted.
* The Target Asset Name shows `jblake`'s own workstation. While this doesn't definitively rule out lateral movement, it gives us more context to investigate further.

Putting this together with what we already know, this activity is riddled with red flags. There's no legitimate reason a payment checker script should be writing secondary PowerShell scripts or initiating outbound connections to unknown external IP addresses.

---

## Phase 5: File Path Verification
We have almost all of the relevant information, but there's one last check before pushing this activity for escalation and deeper analysis: verifying the exact locations of both the downloaded and written scripts.

```cql
scenario_id="EHS-SIA-PROJ-001" user_name="jblake"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, session_id, file_name, file_path, action, process_name])
```

### Results
This search confirmed suspicions about the file being written:
* The downloaded file (`payment_check.ps1`) was placed into the Downloads folder. While normal for a download, we still need to check if it was later moved or deleted to cover tracks.
* The newly created file (`payment_cache.ps1`) was written directly to the Temp directory (`C:/Users/jblake/AppData/Local/Temp/payment_cache.ps1`).

---

## Phase 6: Conclusion and Escalation Recommendation
Now that we have dug deeper and confirmed as much as we currently can, it is time to pool all relevant information together and decide on escalation.

### What We Know
* `acarter`'s events were completely benign and written off.
* `jblake` has no approved changes in the documentation.
* `jblake` downloaded `payment_check.ps1` from `payment-check.example`.
* Immediately after downloading this file, `explorer.exe` started with PID `p-pb-300`.
* With a PPID of `p-pb-300`, PowerShell started with PID `p-pb-301`.
* Immediately after PowerShell started, a new file (`payment_cache.ps1`) was written to `jblake`'s workstation, maintaining the same PID (`p-pb-301`).
* This new file was written to the Temp directory (`C:/Users/jblake/AppData/Local/Temp/payment_cache.ps1`).
* Using the same PID (`p-pb-301`), `jblake`'s workstation formed an outbound encrypted connection (`Port 443`) to an unknown external IP (`203.0.113.81`).
* All of this occurred under Session ID `s-pb-01` on `jblake`'s assigned billing workstation IP (`10.20.1.21`), pointing toward either a compromised account or a potential insider threat.
* The entire sequence took place in just 2 minutes and 10 seconds, indicating either automated malware execution or a skilled threat actor operating quickly.

### What Remains Unknown
* How the attacker gained access. The associated IP belongs to `jblake`, but there were no failed login attempts prior. This could point to credential harvesting, existing endpoint malware, credential stuffing, or an insider threat.
* If this was the result of phishing or malware, whether other users across the network have been affected.
* The exact contents and internal logic of `payment_check.ps1` and `payment_cache.ps1`.
* The complete command-line arguments beyond the basic process start.
* Whether the outbound connection to `203.0.113.81` was direct attacker infrastructure or a Command and Control (`C2`) server.
* What occurred after the connection was established; specifically whether data exfiltration or secondary payload staging took place.
* Whether any persistence mechanisms (such as scheduled tasks or registry run keys) were created.

### Recommendation
Given everything we know and the critical unknowns, I strongly recommend that this incident be immediately escalated for tier-two investigation and incident response. Finding unauthorized script execution and outbound connections on a billing workstation with zero approved changes demands immediate isolation of `EHS-WS-01` and forensic memory acquisition.
