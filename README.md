# Post-Intrusion-Hunt-Signals-After-the-Noise-2
Threat Hunt Report:

Hunt: Signals After the Noise 2 / Hunt 06
Platform: Microsoft Sentinel / Microsoft Defender XDR
Investigation Window: 2025-12-13 09:00 UTC – 2025-12-13 18:00 UTC
Anchor Time: 2025-12-13 09:48:40 UTC
Primary Host: azwks-phtg-01
Primary Account: vmadminusername
Objective: Reconstruct post-access operator activity after the initial break-in was already established.

**1. Executive Summary**

This hunt investigated post-intrusion activity on azwks-phtg-01 after the operator gained access using credential reuse. The investigation confirmed successful lateral movement from 10.0.0.152 to azwks-phtg-01 using vmadminusername, followed by operator staging, PowerShell execution, HealthCloud-themed masquerading, persistence setup, Defender tampering, web-based beaconing, and LSASS memory access.

The operator attempted to blend into the expected PHTG HealthCloud environment by staging tooling under:

C:\ProgramData\PHTG\HealthCloud

They also created persistence through both a Run key and a Startup folder shortcut, added Defender exclusions, registered a custom Windows Application event log source, and used multiple beacon channels under health-cloud.cc.

The most serious late-stage activity was credential access behavior against lsass.exe, where PowerShell running under vmadminusername opened a high-access handle and then triggered ReadProcessMemoryApiCall, confirming memory-read behavior.

This report uses the 29-flag hunt structure provided for the investigation, including lateral movement, persistence, beaconing, Defender tampering, and LSASS access questions.

**2. Scope and Data Sources**
In Scope
Item	Value
Main host	azwks-phtg-01
Main account	vmadminusername
Investigation start	2025-12-13 09:00 UTC
Investigation end	2025-12-13 18:00 UTC
Anchor logon	2025-12-13 09:48:40 UTC
Primary Tables Used
Table	Purpose
DeviceLogonEvents	Logon success/failure, lateral movement, source IP tracking
DeviceProcessEvents	PowerShell, cmd.exe, tool execution, masquerading, script execution
DeviceFileEvents	Startup artifacts and staged files
DeviceRegistryEvents	Run keys, registry persistence, HKLM modifications
DeviceNetworkEvents	Beaconing and outbound communication
DeviceEvents	Defender events, PowerShellCommand telemetry, LSASS API events

**3. High-Level Attack Narrative**

The operator did not appear to brute force access. The successful access was better explained as credential reuse, aligning with MITRE ATT&CK Valid Accounts behavior, where adversaries use legitimate credentials to access systems and blend into normal activity.

After gaining access, the operator moved laterally to azwks-phtg-01 using vmadminusername from 10.0.0.152. This aligns with the broader Remote Services technique, where valid accounts are used to log into services that accept remote connections.

Once on the host, the operator used PowerShell heavily for script execution and configuration changes. MITRE describes PowerShell abuse as a common way to execute code and perform post-exploitation actions on Windows systems.

The operator then staged tooling in a HealthCloud-themed path, hid artifacts with attrib.exe, masqueraded PHTGHealthCloudSvc.exe as bitsadmin.exe, configured Run key and Startup folder persistence, modified Defender exclusions, used web-based C2 endpoints, and finally accessed LSASS memory.

**4. Timeline of Key Activity**
Time UTC	Activity
09:48:40	Lateral movement to azwks-phtg-01 using vmadminusername

09:48	First operator PowerShell script launched from C:\Users\vmAdminUsername\Documents\PHTG\_.ps1

10:11	Temporary Defender exclusion applied for C:\Users\vmAdminUsername\Documents\PHTG

10:12	HealthCloud staging and C2 download/execution sequence observed

10:12	Defender exclusion added for C:\ProgramData\PHTG\HealthCloud\Cache

10:13	Startup folder persistence artifact PHTG HealthCloud.lnk created/reported

10:14	amsi_probe.ps1 executed to test AMSI/PowerShell scanning

10:14	Defender process exclusion added for PHTGHealthCloudSvc.exe

10:14	PowerShell accessed lsass.exe under vmadminusername

10:15+	Additional HealthCloud scripts and beaconing observed
Later window	Startup persistence fired twice

**5. Detailed Findings**

Finding 1 — Initial Access Was Credential Reuse

Flag Answer:

credential reuse

The failed logons did not show the classic pattern of brute force. Instead, the telemetry indicated the operator already had a usable credential and then authenticated successfully. This aligns with MITRE ATT&CK T1078 Valid Accounts, where adversaries abuse legitimate credentials to access systems.

Finding 2 — Lateral Movement to azwks-phtg-01

Flag Answer:

vmadminusername, 10.0.0.152, azwks-phtg-01

DeviceLogonEvents showed successful lateral movement to azwks-phtg-01 using vmadminusername from source IP 10.0.0.152.

This is consistent with MITRE T1021 Remote Services, where an operator authenticates to a remote system using valid credentials.

<img width="1504" height="372" alt="Screenshot 2026-06-08 191425" src="https://github.com/user-attachments/assets/647c6793-9fad-4a7f-9415-81cdc730ffa3" />


Finding 3 — No Confirmed Onward Pivot

Flag Answer:

None

Using the secondary host IP 10.0.0.105 as the source, no successful onward movement was found in DeviceLogonEvents.

This means the operator successfully reached phtg-01, but telemetry did not confirm a further hop from that secondary source.

Finding 4 — First Operator Script

Flag Answer:

C:\Users\vmAdminUsername\Documents\PHTG\_.ps1

The first script launched under the operator’s own account context was _.ps1 from the user’s Documents path.

This script became important later because it temporarily modified Defender exclusions before removing them.

<img width="1498" height="115" alt="image" src="https://github.com/user-attachments/assets/d2e68083-bbe1-48a8-a339-96a6dba43e75" />


Finding 5 — PowerShell Concealment Flags

Flag Answer:

-WindowStyle Hidden -ExecutionPolicy Bypass

The script was launched with -WindowStyle Hidden and -ExecutionPolicy Bypass.

These flags show operator intent: hide the PowerShell window and bypass local script execution restrictions. This maps to PowerShell execution behavior under MITRE T1059.001.

Finding 6 — Operator Tooling Workspace

Flag Answer:

C:\ProgramData\PHTG\HealthCloud

The operator staged tooling under C:\ProgramData\PHTG\HealthCloud, a path that looked like it belonged to the expected HealthCloud software environment.

This path choice helped the operator blend malicious tooling into a legitimate-looking enterprise software directory.

Finding 7 — Hidden Artifact Pattern

Flag Answer:

Cache had 17 attrib modifications, TempCache had 3, and Cache received the heavier treatment.

The operator used attrib.exe with hidden/system-style flags against HealthCloud staging directories.

This maps to MITRE Hide Artifacts behavior, where adversaries hide files, directories, or other artifacts to reduce visibility.

<img width="1540" height="142" alt="image" src="https://github.com/user-attachments/assets/4b52c121-57ae-44e1-bdd1-27da56fad407" />


Finding 8 — Masqueraded Operator Binary

Flag Answer:

PHTGHealthCloudSvc.exe masqueraded as bitsadmin.exe; I separated it from the noise because it was launched by powershell.exe under vmadminusername from C:\ProgramData\PHTG\HealthCloud\, while the other mismatches were normal Microsoft/Windows components running as SYSTEM.

The suspicious binary was PHTGHealthCloudSvc.exe, but its original filename metadata claimed bitsadmin.exe.

This matches MITRE T1036.005 Match Legitimate Name or Location, where adversaries make malicious files appear legitimate by matching names, locations, or metadata associated with trusted software.

<img width="1543" height="329" alt="image" src="https://github.com/user-attachments/assets/c7659b2f-5280-449d-92bc-ebc394fc773c" />


Finding 9 — Registry Modification Volume

Flag Answer:

280

There were 280 registry modification events under vmadminusername on azwks-phtg-01 after lateral movement.

Finding 10 — Run Key Persistence Path

Flag Answer:

HKEY_CURRENT_USER\S-1-5-21-1521579525-3948531162-803360686-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

The operator used a user Run key for persistence.

MITRE T1547.001 Registry Run Keys / Startup Folder describes how entries in Run keys or Startup folders cause programs to execute when a user logs in.
<img width="1495" height="328" alt="image" src="https://github.com/user-attachments/assets/7c835720-d20d-4279-aac3-41bea7d26ed9" />

Finding 11 — Suspicious Run Key Value

Flag Answer:

PHTGHealthCloudTray

The suspicious Run key value was PHTGHealthCloudTray.

Edge auto-launch entries were legitimate, but this value pointed to the operator’s HealthCloud-themed PowerShell persistence.
<img width="1515" height="262" alt="image" src="https://github.com/user-attachments/assets/7b9a55aa-cf8c-4d4a-b23f-a5898220a363" />

Finding 12 — Run Key Persistence Command

Flag Answer:

powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1"

This command was configured to run at user logon.

It used PowerShell with hidden execution and policy bypass flags to execute HealthCloudTray.ps1 from the HealthCloud staging directory.
<img width="1511" height="302" alt="image" src="https://github.com/user-attachments/assets/82ee9789-18dd-4b5a-8053-f09c5b1eebbe" />

Finding 13 — Startup Folder Persistence

Flag Answer:

PHTG HealthCloud.lnk

The operator dropped a Startup folder shortcut named PHTG HealthCloud.lnk.

This was the second persistence mechanism, separate from the Run key. Startup folder persistence is also covered by MITRE T1547.001.
<img width="1512" height="327" alt="image" src="https://github.com/user-attachments/assets/c5a70ef4-7040-4b43-81c7-daf68734bcbf" />

Finding 14 — Custom Event Log Source

Flag Answer:

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud

The operator registered a custom Application event log source under HKLM.

This was not classic persistence. Instead, it enabled the operator’s tooling to write trusted-looking entries into the Windows Application log.

This also maps to MITRE T1112 Modify Registry, where adversaries modify Registry keys to support execution, hiding, or other operational goals.
<img width="1516" height="312" alt="image" src="https://github.com/user-attachments/assets/40f16f9b-eb83-41c7-8e55-20d67fed461b" />

Finding 15 — Healthcheck Loop Count

Flag Answer:

22

The masqueraded binary PHTGHealthCloudSvc.exe ran /healthcheck 22 times.

This recurring pattern showed beacon-style activity disguised as HealthCloud service health checks.

Finding 16 — Encoded PowerShell Beacon Endpoints

Flag Answer:

The beacons contacted https://status.health-cloud.cc/api/checkin?flag=FLAG-09&device=azwks-phtg-01 and then https://status.health-cloud.cc/api/status?flag=FLAG-10&device=azwks-phtg-01, both under health-cloud.cc.

Two encoded PowerShell beacons contacted endpoints under health-cloud.cc.

This maps to MITRE T1071.001 Web Protocols, where adversaries use HTTP or HTTPS to blend command-and-control traffic into normal web traffic.
<img width="1515" height="416" alt="image" src="https://github.com/user-attachments/assets/ac637d49-a5e8-4ac3-83dc-28a28bab6641" />

Finding 17 — Parallel Beacon Channels

Flag Answer:

Running two beacon channels gives the operator resilience because access can continue if one channel is blocked or detected, and it reduces detection clarity by splitting activity across separate traffic patterns that are harder to correlate.

The operator used two channels: the service executable /healthcheck loop and encoded PowerShell web beacons.

This gave the operator operational resilience and made defender correlation harder.

Finding 18 — Download Then Execute Pattern

Flag Answer:

First, it called out to C2 to download something, then it ran the local SvcExe tool right after.

The one-second gap between outbound activity and local execution showed a two-step pattern: pull content from C2, then execute the local tool.

This maps to MITRE T1105 Ingress Tool Transfer, where adversaries transfer tools or files from external infrastructure into a compromised environment.

Finding 19 — Operator PowerShell Domains

Flag Answer:

status.health-cloud.cc, updates.health-cloud.cc

PowerShell reached two domains during post-access activity: status.health-cloud.cc and updates.health-cloud.cc.

Both followed the same HealthCloud-themed domain pattern and supported the broader C2/beaconing behavior.
<img width="1520" height="242" alt="image" src="https://github.com/user-attachments/assets/5b01c264-6a36-4da7-9e93-4ae85ced4e68" />

Finding 20 — AMSI Probe

Flag Answer:

amsi_probe.ps1 tests if AMSI will catch the attacker's PowerShell payloads.

The operator ran amsi_probe.ps1 after outbound communication succeeded.

The script name and context suggest the operator was checking whether AMSI/Defender would detect or block upcoming PowerShell payloads. This supports a Defense Evasion interpretation under MITRE T1562.001 Disable or Modify Tools, which includes modifying security tools to avoid detection.
<img width="1521" height="142" alt="image" src="https://github.com/user-attachments/assets/32f3171f-1bc0-4990-9d6b-b017f114cd6a" />

Finding 21 — Lineage Break Through cmd.exe

Flag Answer:

cmd.exe launched powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\Bin\hc_lineage.ps1" and then "C:\ProgramData\PHTG\HealthCloud\phtg_health_diag_update_FLAG-22.bat"; the operator chained them through cmd.exe to add an intermediate parent process and make the payload lineage less direct.

The operator used cmd.exe as an intermediary launcher twice.

This made process lineage less direct and complicated simple parent-child process analysis.
<img width="1560" height="457" alt="image" src="https://github.com/user-attachments/assets/43a51749-265c-4469-8e4d-a1a2127b5ddc" />

Finding 22 — Defender Tampering

Flag Answer:

They excluded the path C:\ProgramData\PHTG\HealthCloud\Cache and the process C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe.

The operator added Defender exclusions for both a staging path and the masqueraded service binary.

This maps directly to MITRE T1562.001, where adversaries modify security tools to reduce detection and blocking.

Finding 23 — Defender Detection Outcome

Flag Answer:

Defender flagged PHTG HealthCloud.lnk but did not block it; WasExecutingWhileDetected=false shows it was detected after the fact, so the Startup persistence remained.

Defender generated reports for the shortcut, but did not prevent persistence from remaining in place.

The key point is that detection happened, but blocking did not.

Finding 24 — Temporary Defender Exclusion

Flag Answer:

The briefly excluded path was C:\Users\vmAdminUsername\Documents\PHTG; _.ps1 added a Defender exclusion with Add-MpPreference -ExclusionPath $ScriptDir, ran C:\Users\vmAdminUsername\Documents\PHTG\_.ps1, then removed the same exclusion with Remove-MpPreference -ExclusionPath $ScriptDir seconds later; the operator did this to temporarily blind Defender long enough to run the payload while reducing the obvious footprint of a permanent exclusion.

The operator temporarily excluded the script directory, ran the payload, and removed the exclusion.

This was a more careful form of Defender tampering: short-lived enough to reduce obvious permanent configuration changes, but long enough to let the script execute.

Finding 25 — Startup Persistence Actually Fired

Flag Answer:

2

The configured Startup mechanism fired twice during the investigation window.

This proved the persistence was not just configured; it executed.

Finding 26 — Purpose of Custom Event Log Source

Flag Answer:

Registering the PHTGHealthCloud event source lets the operator’s tooling write custom entries into the Windows Application log, which helps the activity blend into trusted HealthCloud-style telemetry that defenders are less likely to scrutinize.

The custom source allowed the operator’s tooling to write into the Windows Application log under a trusted-looking HealthCloud source.

The operational benefit was blending attacker telemetry into a normal administrative logging location.

Finding 27 — LSASS Access Anomaly

Flag Answer:

vmadminusername, powershell.exe

Most LSASS access events were baseline activity from system or security processes. The anomalous one was PowerShell under vmadminusername.

This stood out because a normal user-context PowerShell process accessing LSASS is suspicious.
<img width="1523" height="157" alt="image" src="https://github.com/user-attachments/assets/1bad2de8-ea09-4b4a-acb6-66ef36e7ade6" />

Finding 28 — Full-Access LSASS Handle

Flag Answer:

2047999

The operator’s LSASS access showed two DesiredAccess values. The high-risk value was 2047999.

This represented escalation from a lower access attempt to full-access process access. Full or broad access to LSASS is consistent with credential dumping intent. MITRE T1003.001 LSASS Memory describes adversaries attempting to access credential material stored in LSASS process memory.
<img width="1514" height="422" alt="image" src="https://github.com/user-attachments/assets/dfe6102f-8afe-4e86-b40d-6de4f64f1fc3" />

Finding 29 — Credential Dump Confirmation

Flag Answer:

ReadProcessMemoryApiCall

Opening a full-access handle was not enough to prove dumping. The next confirming ActionType was ReadProcessMemoryApiCall.

This confirmed that the operator actually read memory from LSASS, strengthening the credential-access finding.
<img width="1518" height="270" alt="image" src="https://github.com/user-attachments/assets/8ab0ca98-5d1e-41f1-a777-a90e31f0a34b" />

**MITRE ATT&CK Mapping**

Tactic	Technique	Evidence From Hunt
Initial Access / Defense Evasion / Persistence	T1078 Valid Accounts	Credential reuse with vmadminusername
Lateral Movement	T1021 Remote Services	Successful remote logon to azwks-phtg-01
Execution	T1059.001 PowerShell	PowerShell scripts, encoded commands, hidden execution
Defense Evasion	T1564 Hide Artifacts	attrib.exe hiding HealthCloud artifacts
Defense Evasion	T1036.005 Match Legitimate Name or Location	PHTGHealthCloudSvc.exe masquerading as bitsadmin.exe
Persistence	T1547.001 Registry Run Keys / Startup Folder	Run key value and Startup .lnk
Defense Evasion	T1112 Modify Registry	HKLM event source registration and registry modifications
Command and Control	T1071.001 Web Protocols	HTTPS beaconing to HealthCloud-themed domains
Command and Control / Tool Transfer	T1105 Ingress Tool Transfer	Outbound call followed by local SvcExe execution

**Conclusion**

The hunt confirmed that the operator used credential reuse to access the environment, moved laterally to azwks-phtg-01, and conducted a full post-access sequence. The activity included staging, masquerading, persistence, beaconing, Defender tampering, and credential access.

The attacker deliberately blended into the HealthCloud environment by using PHTG-branded paths, registry names, event log sources, and file names. The operator also used PowerShell and cmd.exe chaining to obscure process lineage, while adding and removing Defender exclusions to reduce exposure.

The final and most severe finding was LSASS memory access by PowerShell under vmadminusername, confirmed by ReadProcessMemoryApiCall. This should be treated as a credential exposure event and escalated for containment, credential rotation, and full incident response.
Defense Evasion	T1027 Obfuscated Files or Information	Encoded PowerShell beacon commands
Defense Evasion	T1562.001 Disable or Modify Tools	Defender exclusions and temporary Defender bypass
Credential Access	T1003.001 LSASS Memory	PowerShell opened and read LSASS memory
