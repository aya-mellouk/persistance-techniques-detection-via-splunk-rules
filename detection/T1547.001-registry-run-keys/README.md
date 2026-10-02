
# T1547.001 : Registry Run Keys / Startup Folder

## MITRE ATT&CK

**Technique:** T1547.001
**Name:** Registry Run Keys / Startup Folder
**Tactic:** Persistence

## Attack Scenario

An attacker establishes persistence by configuring a Registry Run Key or adding a program to a startup folder so that a malicious executable is launched when a user logs on.


## Attack Artifact

The expected artifact is a modification of a Registry Run key.
<img width="807" height="167" alt="image" src="https://github.com/user-attachments/assets/72dd9c9e-b669-4830-a974-db4f8d9fef91" />



## Detection Logic

The detection looks for registry value modifications targeting Run keys.

## Investigation

When the rule triggers, investigate:
* unusual binary paths or script-based payloads. 
* Multi-event detection includes registry modification followed by process execution from non-standard directories or abnormal parent-child process relationships.

## False Positives

Potential legitimate activity includes:

* Software installers
* Application updates
* Legitimate startup applications

Additional filtering should therefore be based on the environment and observed baseline.




