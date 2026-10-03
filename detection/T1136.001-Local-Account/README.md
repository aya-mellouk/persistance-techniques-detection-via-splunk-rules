# T1136.001: Create Account: Local Account

## MITRE ATT&Ck
 **Technique**  T1136.001 /
 **Name** : Create Account: Local Account /
 **Tactic** : Persistence 

## Attack Scenario
An attacker establishes persistence by creating a new local account on a compromised host, using built-in tools such as `net user /add` or the PowerShell cmdlet `New-LocalUser`. The account is often added to the local Administrators group so the attacker keeps privileged access even if the initial foothold is removed.

## Attack Artifact
<img width="665" height="167" alt="image" src="https://github.com/user-attachments/assets/e083d680-9b83-4bba-aa50-8b97df814bdd" />

## Detection Logic
The detection correlates two events on the same host:
1. A process creation event with a suspicious account-creation command line.
2. An EventID 4720 generated within a short time window (less than 60 seconds) after it.
Only transactions containing both events (`eventcount>=2`) and lasting less than 60 seconds are reported.
<img width="776" height="256" alt="image" src="https://github.com/user-attachments/assets/bd4c7947-79e7-4e25-a54e-7dff0a496cf9" />

## Investigation
When the rule triggers, investigate:

- The name of the created account (`TargetUserName`) and whether it matches a legitimate request.
- The account that performed the action and whether it is expected to create accounts.
- Whether the new account was added to the local Administrators group (EventID 4732, SID `S-1-5-32-544`).
- Multi-event detection includes account creation followed by privilege escalation or logon activity from the new account.

## False Positives
Potential legitimate activity includes:

- System administrators creating local accounts manually
- Software installers that create service accounts

Additional filtering should therefore be based on the environment and observed baseline, for example by allowlisting known admin accounts.
