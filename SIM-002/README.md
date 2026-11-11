# SIM-002 Investigation Report
Part one covers a five-day baseline window from 2026/09/28 00:00:00.000 through 2026/10/02 23:59:59.999, while parts two through four switch to a focused window of 2026/10/02 18:00:00.000 to 18:30:00.000.

## Environment Overview: Ellington Health Systems
To maintain consistency across all scenarios, the investigations operate within a simulated healthcare and financial infrastructure. Understanding this baseline allows for accurate behavioral analysis when anomalies occur.

### Accounts and Expected Clients

| Account | Department | Asset | Expected Client IP |
| --- | --- | --- | --- |
| jblake | Billing | EHS-WS-01 | `10.20.1.21` |
| mthompson | Clinical | EHS-WS-02 | `10.20.1.31` |
| amehta | Clinical | EHS-CLIN-WS02 | `10.20.1.32` |
| emartinez | Clinical | EHS-CLIN-WS02 | `10.20.1.22` |
| dbrooks | HR | EHS-HR-WS01 | `10.20.1.41` |
| cbennett | Finance | EHS-EXEC-WS01 | `10.20.1.51` |
| acarter | IT | EHS-IT-WS01 | `10.20.1.61` |
| aokafor | IT | EHS-IT-WS01 | `10.20.1.23` |
| apatel | Clinical | EHS-WS-02 | `10.20.1.33` |

### Asset Inventory

| Asset | Address | Role |
| --- | --- | --- |
| EHS-WS-01 | `10.20.0.11` | Windows billing |
| EHS-WS-02 | `10.20.0.12` | Windows clinical |
| EHS-CLIN-WS02 | `10.20.0.13` | Windows clinical |
| EHS-HR-WS01 | `10.20.0.14` | Windows HR |
| EHS-EXEC-WS01 | `10.20.0.15` | Windows executive |
| EHS-IT-WS01 | `10.20.0.16` | Windows IT |
| EHS-WEB-01 | `10.20.0.21` | Linux web service |
| EHS-APP-01 | `10.20.0.22` | Linux application service |
| EHS-FILE-01 | `10.20.0.23` | File service |
| EHS-LOG-01 | `10.20.0.24` | Logical logging utility |

### Approved Changes

| Reference | Authorized Account | Activity |
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

## Step One
The first thing to do is to take the full five-day window and create a table that shows the authentication records matched to the users across the full set. To do this, I used the query:
```cql
scenario_id="EHS-SIA-SIM-003" event_category="authentication"
| groupBy([user_name], function=count())
```

This separates the results into a simple table that shows the user name and the count of authentication records per each of those users. The result is:

| user_name | _count |
| --- | --- |
| acarter | 24 |
| amehta | 24 |
| aokafor | 24 |
| apatel | 23 |
| cbennett | 25 |
| dbrooks | 24 |
| emartinez | 24 |
| jblake | 24 |
| mthompson | 24 |

## Step Two
Now, we're going to look deeper into Amara's maintenance. The first thing to do is to narrow down the timeframe to between 2026/10/02 18:00:00.000 and 2026/10/02 18:30:00.000. At this point, we narrow down the filters to show us timestamp, event ID, user name, source IP, asset name, session ID, action, outcome, process name, and change reference, using the query:
```cql
scenario_id="EHS-SIA-SIM-003" user_name="aokafor"
| sort(field=@timestamp, order=asc, limit=2000)
```

This gives us a clear view of two relevant events by aokafor. One is a login event coming from 10.20.1.23, which is her assigned IP address on file. The second is an event on EHS-IT-WS01 (our Windows IT service asset) using the change reference CHG-EHS-014, which is our Helpdesk Maintenance authorized for aokafor in our approved changes list. EHS-IT-WS01 appears to be performing inventory maintenance on aokafor, and is utilizing the program inventory_agent.exe to do so.

## Step Three
Next, we want to look at cbennett for any signs of anomalous behavior. To do this, we want to use the table view to see the specific fields and compare them against our employee references, using the query:
```cql
scenario_id="EHS-SIA-SIM-003" user_name="cbennett"
| sort(field=@timestamp, order=asc, limit=2000)
| table([@timestamp, event_id, user_name, src_ip, asset_name, session_id, action, outcome, process_name, change_reference])
```

To start, we can work our way down the table, and immediately we can note that cbennett has no approved changes in the logs. On top of this, we can also note that the source IP address is an unknown public IP (198.51.100.45) rather than the assigned private IP (10.20.1.51).

Notably, the action for aokafor was listed as approved_maintenance while for cbennett, the action was listed as application_access. When including application in the table, there was no application listed for aokafor while for cbennett the application was listed as ehs_finance. The process name for aokafor was listed as inventory_agent.exe and for cbennett it was null. It is also worth noting that the change reference for aokafor listed the official CHG-EHS-014 and was once again null for cbennett. For session ID, we can also see s-bl-help for aokafor and for cbennett it is listed as s-bl-exec.

## Step Four
Here, we write our follow-up notes and make our final decisions. The activity in cbennett's account should be escalated for further review. The evidence doesn't fully prove malicious intent, as the logs only show an application was accessed but nothing more than that.

For aokafor, we can mark this as benign, as her account was approved for maintenance and all of the fields correctly point to the appropriate values, including the internal IP, action, change reference, and event IDs.

For cbennett, we're seeing executive logging, and while their account is an executive workstation asset (EHS-EXEC-WS) which doesn't automatically rule it out, we are seeing a login from an anomalous public IP address and immediate access to ehs_finance, with a null process name and change reference. It is also worth noting that there were no failed login attempts within the timeframe.

### What Remains Unknown or Needs Additional Evidence
For starters, we don't know if this information was malicious in nature, or if this was cbennett logging in from an unknown device, as the logs only show a login and application access. cbennett is associated with finance, which doesn't immediately make it stand out, but the IP address, null process name, and null change reference are major red flags.

If this isn't cbennett, we don't know how they got their initial access, what they were truly able to access, if they were able to spread to any other devices, if there was any malware involved, if there was any data exfiltrated, and if there were any configuration changes.
