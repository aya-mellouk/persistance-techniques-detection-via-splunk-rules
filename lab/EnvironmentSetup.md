# Sysmon Configuration

## Purpose

Sysmon (System Monitor) is a Windows system service that logs detailed system activity to the Windows Event Log

## Configuration

Sysmon was installed on the Windows VM using the SwiftOnSecurity community configuration which pre-filters noisy events and focuses on security-relevant activity.

## Installation

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
