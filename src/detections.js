const detections = {
"credential-access": {
  id: "TA0006",
  name: "Credential Access",
  color: "#ef4444",
  detections: [
    {
      id: 1,
      technique: "T1110.001",
      name: "RDP Brute Force Detection",
      scenario: "Detect RDP brute force attacks by finding source IPs with more than 10 failed RDP login attempts (Logon Type 10) within 15 minutes.",
      requirements: [
        "Monitor EventCode 4625 (failed logons)",
        "Filter for Logon Type 10 (RDP)",
        "Group attempts into 15-minute windows",
        "Calculate attack velocity (attempts per minute)",
        "Alert when >10 failed attempts detected",
        "Show which accounts were targeted",
        "Exclude service accounts and computer accounts"
      ],
      basicQuery: `index=windows EventCode=4625 Logon_Type=10
| bucket _time span=15m
| stats count by _time, src_ip
| where count > 10`,
      alertQuery: `index=windows EventCode=4625 Logon_Type=10
NOT (user="*svc*" OR user="*$" OR user="*SYSTEM*")
| bucket _time span=15m
| stats count as failed_attempts,
      earliest(_time) as first_attempt,
      latest(_time) as last_attempt,
      values(user) as targeted_accounts,
      dc(user) as unique_accounts
by _time, src_ip, dest_host
| where failed_attempts > 10
| eval duration_seconds = last_attempt - first_attempt
| eval duration_minutes = round(duration_seconds / 60, 2)
| eval attempts_per_minute = round(failed_attempts / duration_minutes, 1)
| eval severity = case(
  attempts_per_minute > 20, "critical",
  attempts_per_minute > 10, "high",
  attempts_per_minute > 5, "medium",
  1=1, "low"
)
| eval description = "RDP Brute Force: " . src_ip . " attempted " . failed_attempts . " failed logins against " . unique_accounts . " accounts in " . duration_minutes . " min (Rate: " . attempts_per_minute . " attempts/min)"
| eval mitre_technique = "T1110.001 - Brute Force: Password Guessing"
| eval mitre_tactic = "TA0006 - Credential Access"
| table _time, src_ip, dest_host, failed_attempts, duration_minutes, attempts_per_minute, unique_accounts, targeted_accounts, severity, description
| sort - attempts_per_minute`
    },
    {
      id: 2,
      technique: "T1558.003",
      name: "Kerberoasting Detection",
      scenario: "Detect Kerberoasting by finding Kerberos service ticket requests (EventCode 4769) using RC4 encryption for service accounts.",
      requirements: [
        "Monitor EventCode 4769 (Kerberos service ticket)",
        "Filter for RC4 encryption (0x17 or 0x18)",
        "Filter for successful requests (Status=0x0)",
        "Exclude computer accounts (ServiceName ending with $)",
        "Count ticket requests per user",
        "Show which services were targeted",
        "Alert when user requests >5 service tickets"
      ],
      basicQuery: `index=windows EventCode=4769
(TicketEncryptionType="0x17" OR TicketEncryptionType="0x18")
Status="0x0"
NOT ServiceName="*$"
| stats count as ticket_requests,
      values(ServiceName) as services_targeted,
      dc(ServiceName) as unique_services
by user
| where ticket_requests > 5
| sort - ticket_requests`,
      alertQuery: `index=windows EventCode=4769
(TicketEncryptionType="0x17" OR TicketEncryptionType="0x18")
Status="0x0"
NOT ServiceName="*$"
| stats count as ticket_requests,
      values(ServiceName) as services_targeted,
      dc(ServiceName) as unique_services,
      values(IpAddress) as source_ips,
      values(TicketEncryptionType) as encryption_types
by user
| where ticket_requests > 5
| eval severity = case(
  ticket_requests > 20, "critical",
  ticket_requests > 10, "high",
  ticket_requests > 5, "medium",
  1=1, "low"
)
| eval description = "Kerberoasting: User '" . user . "' requested " . ticket_requests . " service tickets using RC4 encryption, targeting " . unique_services . " unique services"
| eval mitre_technique = "T1558.003 - Kerberoasting"
| eval mitre_tactic = "TA0006 - Credential Access"
| table _time, user, ticket_requests, unique_services, services_targeted, source_ips, severity, description
| sort - ticket_requests`
    },
    {
      id: 3,
      technique: "T1558.001",
      name: "Golden Ticket Detection",
      scenario: "Detect Golden Ticket attacks by finding Kerberos TGT requests (EventCode 4768) with unusual encryption types or from unusual sources.",
      requirements: [
        "Monitor EventCode 4768 (Kerberos TGT request)",
        "Filter for successful requests (Status=0x0)",
        "Check for RC4 encryption (0x17, 0x18) OR null/empty IP addresses",
        "Count TGT requests per user",
        "Show encryption types and source IPs",
        "Alert when user has multiple suspicious requests"
      ],
      basicQuery: `index=windows EventCode=4768
Status="0x0"
(TicketEncryptionType="0x17" OR TicketEncryptionType="0x18" OR isnull(IpAddress) OR IpAddress="")
| stats count as tgt_requests,
      values(TicketEncryptionType) as encryption_types,
      values(IpAddress) as source_ips
by user
| where tgt_requests > 3
| sort - tgt_requests`,
      alertQuery: null
    },
    {
      id: 4,
      technique: "T1110.003",
      name: "Password Spray Detection",
      scenario: "Detect password spraying against service accounts by finding failed logins for accounts containing 'svc' or 'service' from the same source IP.",
      requirements: [
        "Monitor EventCode 4625 (failed logons)",
        "Filter for usernames containing 'svc' or 'service'",
        "Group by source IP within 15-minute windows",
        "Count unique service accounts targeted",
        "Show list of targeted accounts",
        "Alert when IP targets 5+ different service accounts"
      ],
      basicQuery: `index=windows EventCode=4625
(user="*svc*" OR user="*service*")
| bucket _time span=15m
| stats dc(user) as account_count,
      count as total_attempts,
      values(user) as accounts_targeted
by _time, src_ip
| where account_count >= 5
| sort - account_count`,
      alertQuery: null
    },
    {
      id: 5,
      technique: "T1003.001",
      name: "LSASS Memory Access",
      scenario: "Detect LSASS memory dumping (credential theft) by finding processes accessing lsass.exe.",
      requirements: [
        "Monitor EventCode 4663 (object access)",
        "Filter for ObjectName containing 'lsass.exe'",
        "Show which processes accessed LSASS",
        "Show which users ran those processes",
        "Exclude legitimate system processes",
        "Count access attempts"
      ],
      basicQuery: `index=windows EventCode=4663
ObjectName="*lsass.exe*"
NOT (ProcessName="*wininit.exe*" OR ProcessName="*services.exe*" OR ProcessName="*svchost.exe*" OR ProcessName="*csrss.exe*")
| stats count as access_count,
      values(ProcessName) as accessing_processes,
      values(user) as accessing_users
by ComputerName
| sort - access_count`,
      alertQuery: null
    },
    {
      id: 6,
      technique: "T1621",
      name: "MFA Fatigue Attack",
      scenario: "Detect MFA fatigue attacks by finding users with more than 15 failed MFA attempts in 10 minutes.",
      requirements: [
        "Monitor Duo logs (sourcetype=duo)",
        "Filter for MFA failures",
        "Group by user and source IP in 10-minute windows",
        "Calculate duration and attempts per minute",
        "Alert when >15 failures detected",
        "Exclude test accounts"
      ],
      basicQuery: `index=auth sourcetype=duo
mfa_result="failure"
NOT user IN ("test_user", "scanner_account")
| bucket _time span=10m
| stats count as failure_count,
      earliest(_time) as first_failure,
      latest(_time) as last_failure
by _time, user, src_ip
| where failure_count > 15
| eval duration_minutes = round((last_failure - first_failure) / 60, 2)
| eval attempts_per_minute = round(failure_count / duration_minutes, 1)
| sort - failure_count`,
      alertQuery: null
    }
  ]
},

"Persistence": {
  id: "TA0003",
  name: "Persistence",
  color: "#f59e0b",
  detections: [
    {
      id: 1,
      technique: "T1136.001",
      name: "New Admin Account Creation",
      scenario: "Alert when a new user account is created AND added to the local Administrators group within 10 minutes.",
      requirements: [
        "Monitor EventCode 4720 (account created)",
        "Monitor EventCode 4732 (added to local group)",
        "Correlate both events within 10 minutes",
        "Filter for 'Administrators' group only",
        "Exclude known IT administrators",
        "Exclude service accounts and computer accounts",
        "Exclude maintenance windows"
      ],
      basicQuery: `index=windows (EventCode=4720 OR EventCode=4732) Group_Name="Administrators"
| transaction TargetUserName maxspan=10m
| search EventCode=4720 EventCode=4732`,
      alertQuery: `index=windows (EventCode=4720 OR EventCode=4732) Group_Name="Administrators"
NOT (SubjectUserName="admin_jsmith" OR SubjectUserName="svc_provisioning" OR SubjectUserName="SYSTEM")
NOT (SubjectUserName="svc_*" OR SubjectUserName="*$")
NOT (TargetUserName="sql_service" OR TargetUserName="backup_admin" OR TargetUserName="monitoring_svc")
NOT (TargetUserName="svc_*" OR TargetUserName="test_*" OR TargetUserName="*$")
| transaction TargetUserName maxspan=10m
| search EventCode=4720 EventCode=4732
| where NOT (date_wday="sunday" AND date_hour >= 2 AND date_hour <= 4)
| eval description = "CRITICAL: New admin account '" . TargetUserName . "' created by '" . SubjectUserName . "' and added to Administrators group"
| eval mitre_technique = "T1136.001 - Create Account: Local Account"
| eval mitre_tactic = "TA0003 - Persistence"
| eval severity = "critical"
| table _time, TargetUserName, SubjectUserName, ComputerName, severity, description
| sort - _time`
    },
    {
      id: 2,
      technique: "T1053.005",
      name: "Scheduled Task Persistence",
      scenario: "Detect malicious scheduled tasks created to run at system startup from suspicious locations.",
      requirements: [
        "Monitor EventCode 4698 (scheduled task created)",
        "Check TaskContent for startup triggers (Logon, Boot, Startup)",
        "Check TaskContent for suspicious paths (Temp, AppData, Downloads)",
        "Count tasks created per user",
        "Show task names and creators"
      ],
      basicQuery: `index=windows EventCode=4698
(TaskContent="*Logon*" OR TaskContent="*Boot*" OR TaskContent="*Startup*")
(TaskContent="*Temp*" OR TaskContent="*AppData*" OR TaskContent="*Downloads*")
| stats count as task_count,
      values(TaskName) as tasks_created
by user, ComputerName
| sort - task_count`,
      alertQuery: null
    },
    {
      id: 3,
      technique: "T1098.003",
      name: "Domain Admin Addition",
      scenario: "Alert on ANY user being added to Domain Admins group.",
      requirements: [
        "Monitor EventCode 4728 (member added to global group)",
        "Filter for 'Domain Admins' group",
        "Show who was added",
        "Show who added them",
        "Mark as CRITICAL",
        "Show every occurrence"
      ],
      basicQuery: `index=windows EventCode=4728
Group_Name="Domain Admins"
| eval severity = "CRITICAL"
| table _time, MemberName, SubjectUserName, ComputerName, severity
| sort - _time`,
      alertQuery: null
    }
  ]
},

"Lateral Movement": {
  id: "TA0008",
  name: "Lateral Movement",
  color: "#8b5cf6",
  detections: [
    {
      id: 1,
      technique: "T1550.002",
      name: "Pass-the-Hash Detection",
      scenario: "Detect pass-the-hash by finding NTLM authentication where users authenticate from multiple different workstations.",
      requirements: [
        "Monitor EventCode 4776 (NTLM authentication)",
        "Filter for successful authentication",
        "Count distinct workstations per user",
        "Group by 1-hour windows",
        "Alert when user authenticates from 3+ workstations",
        "Show list of workstations used"
      ],
      basicQuery: `index=windows EventCode=4776
Status="0x0"
| bucket _time span=1h
| stats dc(Workstation) as workstation_count,
      values(Workstation) as workstations_used
by _time, user
| where workstation_count >= 3
| sort - workstation_count`,
      alertQuery: null
    }
  ]
},

"execution": {
  id: "TA0002",
  name: "Execution",
  color: "#06b6d4",
  detections: [
    {
      id: 1,
      technique: "T1059.001",
      name: "PowerShell Spawned by Office",
      scenario: "Detect malicious documents by finding PowerShell spawned by Office applications (Word, Excel, Outlook).",
      requirements: [
        "Monitor EventCode 4688 (process creation)",
        "Filter for PowerShell.exe",
        "Check if parent is Word, Excel, or Outlook",
        "Count executions per user",
        "Show command lines and parent processes"
      ],
      basicQuery: `index=windows EventCode=4688
Process_Name="*powershell.exe"
(ParentProcessName="*winword.exe" OR ParentProcessName="*excel.exe" OR ParentProcessName="*outlook.exe")
| stats count as executions,
      values(CommandLine) as commands_used,
      values(ParentProcessName) as parent_processes
by user, ComputerName
| sort - executions`,
      alertQuery: null
    },
    {
      id: 2,
      technique: "T1218",
      name: "Living-off-the-Land Binaries",
      scenario: "Detect abuse of legitimate Windows binaries (certutil, bitsadmin, regsvr32) for file downloads.",
      requirements: [
        "Monitor EventCode 4688 (process creation)",
        "Filter for certutil.exe, bitsadmin.exe, regsvr32.exe",
        "Check CommandLine for download indicators",
        "Count executions per user",
        "Show command lines and tools used"
      ],
      basicQuery: `index=windows EventCode=4688
(Process_Name="*certutil.exe*" OR Process_Name="*bitsadmin.exe*" OR Process_Name="*regsvr32.exe*")
(CommandLine="*download*" OR CommandLine="*transfer*" OR CommandLine="*urlcache*" OR CommandLine="*http*" OR CommandLine="*scrobj.dll*")
| stats count as executions,
      values(CommandLine) as commands_used,
      values(Process_Name) as tools_used
by user, ComputerName
| sort - executions`,
      alertQuery: null
    }
  ]
},

"exfiltration": {
  id: "TA0010",
  name: "Exfiltration",
  color: "#10b981",
  detections: [
    {
      id: 1,
      technique: "T1041",
      name: "Abnormal Outbound Traffic",
      scenario: "Detect data exfiltration by finding internal hosts sending more than 10GB to external IPs in 1 hour.",
      requirements: [
        "Monitor firewall logs (action='allowed')",
        "Exclude internal destinations (RFC1918)",
        "Group by source IP in 1-hour windows",
        "Sum bytes_out",
        "Convert to GB",
        "Alert when >10GB sent"
      ],
      basicQuery: `index=firewall action="allowed"
NOT (
  cidrmatch("10.0.0.0/8", dest_ip)
  OR cidrmatch("172.16.0.0/12", dest_ip)
  OR cidrmatch("192.168.0.0/16", dest_ip)
)
| bucket _time span=1h
| stats sum(bytes_out) as outgoing_bytes by _time, src_ip
| eval GB = outgoing_bytes / 1024 / 1024 / 1024
| where GB > 10
| sort - GB`,
      alertQuery: null
    }
  ]
},

"impact": {
  id: "TA0040",
  name: "Impact",
  color: "#dc2626",
  detections: [
    {
      id: 1,
      technique: "T1485",
      name: "Mass File Deletion",
      scenario: "Detect potential ransomware by finding users who deleted more than 100 files in 5 minutes.",
      requirements: [
        "Monitor EventCode 4663 (object access)",
        "Filter for DELETE operations",
        "Group deletions into 5-minute windows",
        "Count distinct files deleted per user",
        "Alert when >100 files deleted",
        "Exclude service accounts"
      ],
      basicQuery: `index=windows EventCode=4663
ObjectName="*"
AccessMask="*DELETE*"
NOT (user="*svc*" OR user="*$" OR user="SYSTEM")
| bucket _time span=5m
| stats dc(ObjectName) as deleted_files,
      values(ObjectName) as file_list
by _time, user, ComputerName
| where deleted_files > 100
| sort - deleted_files`,
      alertQuery: `index=windows EventCode=4663
ObjectName="*"
AccessMask="*DELETE*"
NOT (user="*svc*" OR user="*$" OR user="SYSTEM")
| bucket _time span=5m
| stats dc(ObjectName) as deleted_files,
      values(ObjectName) as file_list,
      earliest(_time) as first_deletion,
      latest(_time) as last_deletion
by _time, user, ComputerName
| where deleted_files > 100
| eval duration_seconds = last_deletion - first_deletion
| eval duration_minutes = round(duration_seconds / 60, 2)
| eval deletion_rate = round(deleted_files / 5, 1)
| eval severity = case(
  deleted_files >= 500, "critical",
  deleted_files >= 300, "high",
  deleted_files >= 100, "medium",
  1=1, "low"
)
| eval description = "Mass File Deletion: User '" . user . "' deleted " . deleted_files . " files on " . ComputerName . " (Rate: " . deletion_rate . " files/min)"
| eval mitre_technique = "T1485 - Data Destruction"
| eval mitre_tactic = "TA0040 - Impact"
| table _time, user, ComputerName, deleted_files, deletion_rate, severity, description
| sort - deleted_files`
    }
  ]
}
};
export default detections;
