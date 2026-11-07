# T1037.001 : Boot or Logon Initialization Scripts: Logon Script (Windows)

## Description 

Windows can run a script automatically every time a user logs on. An attacker can abuse the `UserInitMprLogonScript` registry value to run a malicious script or binary at each logon. It gives persistence, survives reboots, and needs no admin rights because it lives in the user's own registry hive.

## Attack Scenario

An attacker gains access to a user account and wants to stay on the machine after a reboot. They run `reg add HKCU\Environment /v UserInitMprLogonScript /d "C:\Users\Public\script.bat"` to point the value at a malicious script. The next time the user logs on, `userinit.exe` launches the script automatically. The payload then runs at every logon without any further action from the attacker.
<img width="687" height="45" alt="image" src="https://github.com/user-attachments/assets/9630c7e4-5c51-4935-b9b8-34f4fa3f9831" />

## Detection Logic
Detect the creation or modification of the registry value `UserInitMprLogonScript` under the `Environment` key, using Sysmon Event ID 13 (Registry value set). This value is rarely used legitimately, so any change is worth reviewing.
<img width="917" height="265" alt="image" src="https://github.com/user-attachments/assets/8a08553b-9238-4f38-9f79-8ea44051a1f6" />

## Investigation

1. Read `Details` to see which script or binary the value points to.
2. Check `Image` to see which process made the change (`reg.exe`, `powershell.exe`, an unexpected binary).
3. Check `User` and `host`: who is affected and is the change expected?
4. Inspect the script: location, content, hash, signature, and when it was created.
5. Look for a process spawned by `userinit.exe` at the next logon (other than `explorer.exe`).
6. If malicious: remove the registry value, delete the script, reset the user's credentials.

## False Positives

- Legitimate admin or corporate logon scripts configured by IT.
- Software or VDI tools that register a logon-time helper.

Allowlist known script paths once they are verified.
