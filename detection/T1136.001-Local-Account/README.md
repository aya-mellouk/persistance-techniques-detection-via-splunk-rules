# T1136.001: Create Account: Local Account

## MITRE ATT&CK

| Field | Value |
|---|---|
| **Technique** | T1136.001 |
| **Name** | Create Account: Local Account |
| **Tactic** | Persistence |

## Attack Scenario

An attacker establishes persistence by creating a new local account on a compromised host, using built-in tools such as `net user /add` or the PowerShell cmdlet `New-LocalUser`. The account is often added to the local Administrators group so the attacker keeps privileged access even if the initial foothold is removed.

## Attack Artifact

The expected artifacts are:

- A process creation event (Sysmon EventID 1) for `net.exe`, `net1.exe`, `powershell.exe` or `cmd.exe`, with a command line containing `user ... /add` or `New-LocalUser`.
- A Windows Security EventID 4720 (a user account was created).
- Optionally, EventID 4732 (member added to a security-enabled local group) when the account is added to the Administrators group.

## Detection Logic

The detection correlates two events on the same host:

1. A process creation event with a suspicious account-creation command line.
2. An EventID 4720 generated within a short time window (less than 60 seconds) after it.

Only transactions containing both events (`eventcount>=2`) and lasting less than 60 seconds are reported.

```spl
(index=wineventlog EventCode=4720)
OR
(index=sysmon EventCode=1
  (
    ((Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="*user*" CommandLine="*/add*")
    OR ((Image="*\\powershell.exe" OR Image="*\\pwsh.exe") CommandLine="*New-LocalUser*")
  )
)
| eval host=lower(coalesce(Computer, host))
| transaction host startswith=(EventCode=1) endswith=(EventCode=4720) maxspan=60s
| where eventcount>=2 AND duration<60
| table _time host duration eventcount CommandLine ParentImage TargetUserName SubjectUserName
```

## Investigation

When the rule triggers, investigate:

- The name of the created account (`TargetUserName`) and whether it matches a known naming convention or a legitimate request.
- The account that performed the action (`SubjectUserName`) and whether it is expected to create accounts.
- Unusual parent-child process relationships (for example `winword.exe`, `wmiprvse.exe` or `w3wp.exe` spawning `cmd.exe` or `powershell.exe`).
- Whether the new account was added to the local Administrators group (EventID 4732, SID `S-1-5-32-544`).
- Subsequent activity by the new account (EventID 4624 logons, especially remote logons).
- Multi-event detection includes account creation followed by privilege escalation or logon activity from the new account.

## False Positives

Potential legitimate activity includes:

- System administrators creating local accounts manually
- Provisioning or deployment scripts (imaging, SCCM, Ansible)
- Software installers that create service accounts

Additional filtering should therefore be based on the environment and observed baseline, for example by allowlisting known admin accounts, provisioning servers and expected parent processes.
