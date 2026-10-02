# Detection Engineering Lab

A hands-on Detection Engineering lab focused on developing, testing and tuning SIEM detection rules for Windows attack techniques.

## Objectives

* Understand attacker behavior and attack artifacts
* Analyze Windows, Sysmon and PowerShell logs
* Develop Splunk SPL detection rules
* Reduce false positives through detection tuning
* Design detection logic for MITRE ATT&CK techniques

## Lab Architecture

The lab consists of:

* Windows VM : monitored endpoint
* Ubuntu VM : Splunk server
* Sysmon : endpoint telemetry
* Splunk Universal Forwarder : log collection
* Splunk : SIEM and detection platform
* Atomic Red Team : attack simulation

## Detection Workflow

For each technique:

1. Research the technique and Understand the attacker behavior
2. Identify relevant telemetry
3. Execute a controlled Atomic Red Team test
4. Analyze generated events
5. Write the detection rule based on the attack signatures and behaviour
6. Test the rule
7. Tune false positives


## Detection Coverage

| Technique         | MITRE ATT&CK | Telemetry          | Splunk Detection | Tested |
| ----------------- | ------------ | ------------------ | ---------------- | ------ |
| Registry Run Keys | T1547.001    | Sysmon Event ID 13 | ✅                | ✅      |
| Windows Services  | T1543.003    | Sysmon Event ID 13 | ✅                | ✅      |
| Scheduled Task    | T1053.005    | Windows/Sysmon     | ✅                | ✅      |

## Detection Philosophy

The goal of this project is not to build detections based only on Event IDs.

Instead, detections are developed around **behavioral patterns and attack artifacts**.

For example:

* suspicious registry modification
* unusual service binary path
* PowerShell execution from a service
* executable written to an unusual location
* persistence-related registry changes
* suspicious parent/child process relationships

## Repository Structure

```text
detections/
    technique/
        README.md
        detection.spl
        screenshots/

lab/
README.md
```

## Current Progress

This repository is continuously updated as new attack techniques are researched, simulated and converted into SIEM detections.

## Disclaimer

This project is intended for educational and defensive security research in an isolated laboratory environment.
