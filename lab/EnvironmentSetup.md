# Sysmon Configuration

## Purpose

Sysmon (System Monitor) is a Windows system service that logs detailed system activity to the Windows Event Log

## Configuration

Sysmon was installed on the Windows VM using the SwiftOnSecurity community configuration which pre-filters noisy events and focuses on security-relevant activity.

## Installation

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```
# Splunk configuration

## Purpose

Splunk is a powerful data platform that collects, indexes, and analyzes massive volumes of machine-generated data.
it works by using  a **Forwarder** to gather raw logs and system data from applications, servers, and devices. This data is then sent to an **Indexer** for structured storage, where users can instantly query it using **Search Processing Language (SPL)** to find security threats or IT issues.

## Configuration

- Install Splunk
sudo dpkg -i splunk-*.deb

- Start and accept license (set admin password on first run)
sudo /opt/splunk/bin/splunk start --accept-license

- Enable auto-start on boot
sudo /opt/splunk/bin/splunk enable boot-start

- Enable receiving on port 9997 (for Splunk UF connections)
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:password

-The Splunk Web UI is accessible at `http://<splunk-machine-ip>:8000`

# Splunk Universal Forwarder

## Purpose

The Splunk Universal Forwarder (UF) was installed on the Windows VM to forward event logs to Splunk. It is configured by two files, Inputs.conf and Output.conf.

## Configuration

--> Inputs.conf (what to collect)
>  C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf


```
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = sysmon
disabled = 0
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = wineventlog
disabled = 0

[WinEventLog://Security]
index = wineventlog
disabled = 0

[WinEventLog://System]
index = wineventlog
disabled = 0
```

--> outputs.conf: (Where to send it)
>  C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf

```
[tcpout]
defaultGroup = splunk_indexer

[tcpout:splunk_indexer]
server = <SPLUNK_UBUNTU_IP>:9997
```
--> clean events from an index:
first stop splunk run this command and start again
```
$SPLUNK_HOME/bin/splunk clean eventdata -index <index_name>
```
# Atomic red team

## Purpose

Atomic red team provides us with scripts that represent common attack and techniques  emulation
**Invoke-AtomicTest** is the powershell framework of atomic.

## Useful commands

- List available techniques 
Invoke-AtomicTest T1059 -ShowDetailsBrief 
- Run a specific technique 
Invoke-AtomicTest T1059 
- Run a specific test number 
Invoke-AtomicTest T1059.001 -TestNumbers 1 
- Check prerequisites 
Invoke-AtomicTest T1059 -CheckPrereqs 
- Install prerequisites 
Invoke-AtomicTest T1059 -GetPrereqs 
- Clean up after a test 
Invoke-AtomicTest T1059 -Cleanup
- Disable the powershell execution policy blocking 
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force




