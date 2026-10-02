
# T1547.001 — Registry Run Keys / Startup Folder

## MITRE ATT&CK

**Technique:** T1547.001
**Name:** Registry Run Keys / Startup Folder
**Tactic:** Persistence

## Attack Scenario

An attacker establishes persistence by configuring a Registry Run Key so that a malicious executable is launched when a user logs on.

## Attack Simulation

The technique was simulated using Atomic Red Team.

### Test

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

## Telemetry

Relevant telemetry:

* Sysmon Event ID 13 — Registry value modification
* Windows registry
* Splunk

## Attack Artifact

The expected artifact is a modification of a Registry Run key.

Example pattern:

```text
HKU\<user>\Software\Microsoft\Windows\CurrentVersion\Run
```

## Detection Logic

The detection looks for registry value modifications targeting Run keys.

```spl
index=sysmon EventCode=13 EventType=SetValue
TargetObject="*\\CurrentVersion\\Run*"
| table _time EventType TargetObject Details User
| sort -_time
```

## Investigation

When the rule triggers, investigate:

* Registry path
* Registry value
* Executable path
* User account
* Process responsible for the modification
* Parent process
* File reputation
* Execution timeline

## False Positives

Potential legitimate activity includes:

* Software installers
* Application updates
* Legitimate startup applications

Additional filtering should therefore be based on the environment and observed baseline.

## Validation

The detection was tested against the Atomic Red Team simulation.

Screenshots:

`./screenshots/`

## MITRE Mapping

T1547.001 — Registry Run Keys / Startup Folder

## Lessons Learned

Document what telemetry was available, what fields were useful, and how the initial query was improved.
