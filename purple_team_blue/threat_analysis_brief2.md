## Threat Analysis Brief: UNC3944 - Remote Access Software (T1219) & OS Credential Dumping (T1003.001)

**Date:** October 26, 2023
**Analyst:** Senior Cybersecurity Threat Analyst
**Target Environment:** Single Windows 10/11 endpoint used by a software developer at an energy engineering firm.

---

### Executive Summary

This brief details detection strategies for two significant MITRE ATT&CK techniques employed by UNC3944 (Scattered Spider): **Remote Access Software (T1219)** and **OS Credential Dumping: LSASS Memory (T1003.001)**. UNC3944 is a financially motivated threat actor heavily relying on social engineering. Effective detection of these techniques is critical as they enable persistent access, command and control, privilege escalation, and lateral movement, leading to severe financial impact through ransomware and data exfiltration.

---

### 1. Threat Classification

*   **Threat Type:** Technique / Behavior
*   **MITRE ATT&CK IDs:**
    *   T1219: Remote Access Software
    *   T1003.001: OS Credential Dumping: LSASS Memory
*   **Threat Severity Level:** High / Critical
    *   **T1219:** High, as it provides persistent interactive control, enabling various subsequent attack stages.
    *   **T1003.001:** Critical, as it directly leads to the compromise of user credentials, which are foundational for privilege escalation and lateral movement.

---

### 2. Data Source Analysis

Given the Windows 10/11 endpoint, the following log sources and event types are optimal:

**For T1219: Remote Access Software**

*   **Log Source:** Windows Event Logs (Security, System, Application), Sysmon, Endpoint Detection and Response (EDR) Telemetry, Network Flow Logs/Firewall Logs.
*   **Required Log Fields/Event Types:**
    *   **Process Creation (Sysmon Event ID 1 / Windows Security Event ID 4688):**
        *   `Image`: Process executable path (e.g., `C:\Program Files (x86)\AnyDesk\AnyDesk.exe`, `C:\Program Files (x86)\ScreenConnect\Client\ScreenConnect.ClientService.exe`).
        *   `CommandLine`: Arguments used during execution (e.g., installation flags, connection parameters).
        *   `ParentImage`: Parent process that launched the remote access tool (e.g., `explorer.exe`, `cmd.exe`, `powershell.exe`, or a web browser for initial download/execution).
        *   `User`: User account executing the process.
    *   **Network Connection (Sysmon Event ID 3 / Windows Security Event ID 5156):**
        *   `Image`: Process initiating the network connection.
        *   `DestinationIp`: IP address of the remote access server.
        *   `DestinationPort`: Common ports for remote access tools (e.g., 80, 443, 5938 for TeamViewer, 6568, 7070 for AnyDesk, 8040 for ScreenConnect).
        *   `Initiated`: Boolean indicating outbound connection.
    *   **File Creation (Sysmon Event ID 11):**
        *   `TargetFilename`: Creation of executables in unusual directories (e.g., `%TEMP%`, user profile subdirectories).
    *   **Registry Modification (Sysmon Event ID 12/13/14 / Windows Security Event ID 4657):**
        *   `TargetObject`: Registry paths related to auto-start or service installation for remote access tools (e.g., `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `HKLM\SYSTEM\CurrentControlSet\Services`).
        *   `Details`: Value assigned to the registry key.

**For T1003.001: OS Credential Dumping: LSASS Memory**

*   **Log Source:** Sysmon, Windows Event Logs (Security), EDR Telemetry.
*   **Required Log Fields/Event Types:**
    *   **Process Access (Sysmon Event ID 10 / Windows Security Event ID 4663 with specific access masks):**
        *   `SourceImage`: Process attempting to open `lsass.exe`.
        *   `TargetImage`: `lsass.exe`.
        *   `GrantedAccess`: Access rights requested (e.g., `0x1F0FFF` for full access, `0x1410` for `PROCESS_VM_READ|PROCESS_QUERY_INFORMATION`, `0x1000` for `PROCESS_VM_READ`). These are critical for memory dumping.
        *   `CallTrace`: Call stack for the process access (advanced).
    *   **Process Creation (Sysmon Event ID 1 / Windows Security Event ID 4688):**
        *   `Image`: Execution of known credential dumping tools (e.g., `mimikatz.exe`, `procdump.exe`).
        *   `CommandLine`: Specific command-line arguments used by these tools (e.g., `sekurlsa::logonpasswords`, `-ma lsass.exe`).
        *   `ParentImage`: Process that launched the dumping tool (e.g., `cmd.exe`, `powershell.exe`).
        *   `User`: User account executing the tool (especially if non-SYSTEM).
    *   **File Creation (Sysmon Event ID 11):**
        *   `TargetFilename`: Creation of `lsass.dmp` or other memory dump files in unusual locations.
    *   **Module Load (Sysmon Event ID 7):**
        *   Loading of DLLs associated with credential dumping techniques into `lsass.exe` (e.g., `comsvcs.dll` when used for `MiniDumpWriteDump`).

---

### 3. Detection Strategy

**For T1219: Remote Access Software**

*   **Detection Approach:** Behavioral, Signature-based, Statistical.
*   **Key Indicators & Artifacts:**
    *   **Process-based:**
        *   Execution of known remote access tool executables (e.g., `anydesk.exe`, `screenconnect.client.exe`, `ateraservice.exe`, `teamviewer.exe`).
        *   Processes spawned by unusual parent processes (e.g., a browser spawning a remote access tool installer outside of a user's normal downloads folder).
        *   Remote access tools running from unexpected directories (e.g., `%TEMP%`, user download folders not `Program Files`).
    *   **Network-based:**
        *   Outbound network connections to known remote access infrastructure IP addresses/domains (IOCs).
        *   Connections on non-standard ports to external IPs associated with remote access.
        *   Sustained high-volume outbound traffic indicative of active remote session or data transfer via the tool.
    *   **System-based:**
        *   New services or registry `Run` keys created for persistence, matching known remote access tools.
        *   Unusual device/MFA registration events (as mentioned in the threat report) that often accompany new remote access.
*   **Evasion Techniques & Variants:**
    *   **Living Off The Land Binaries (LOLBins):** Using legitimate tools like `mstsc.exe` (Remote Desktop), `netsh` for firewall bypass, or `bitsadmin` for downloading payloads.
    *   **Obfuscation:** Renaming executables, packing/encrypting payloads, using custom compiled versions.
    *   **Social Engineering:** Bypassing technical controls through user manipulation (e.g., convincing a developer to install a "support tool").
    *   **DNS Tunneling/Covert Channels:** Using less obvious network communication methods.

**For T1003.001: OS Credential Dumping: LSASS Memory**

*   **Detection Approach:** Behavioral, Signature-based.
*   **Key Indicators & Artifacts:**
    *   **Process-based:**
        *   A non-system process (especially one not typically involved in debugging/system management like `taskmgr.exe`, `procdump.exe`, `mimikatz.exe`, `powershell.exe`) attempting to open `lsass.exe` with `PROCESS_VM_READ` or `PROCESS_QUERY_INFORMATION` access rights.
        *   Command-line arguments containing keywords like `sekurlsa`, `logonpasswords`, `lsass.exe`, `procdump`, `minidump`.
        *   `Comsvcs.dll` being loaded into `lsass.exe` process (Sysmon Event ID 7 with `Image` field as `lsass.exe` and `ImageLoaded` as `comsvcs.dll`).
    *   **File-based:**
        *   Creation of large `.dmp` files (e.g., `lsass.dmp`) in unexpected directories (e.g., user's desktop, `%TEMP%`, `%APPDATA%`).
*   **Evasion Techniques & Variants:**
    *   **Reflective DLL Injection:** Injecting Mimikatz or similar functionality directly into a legitimate process's memory to avoid dropping a standalone executable.
    *   **Memory Obfuscation:** Techniques to hide the credential dumping logic in memory.
    *   **PowerShell/Scripting:** Using in-memory PowerShell scripts (e.g., `Invoke-Mimikatz`) which may not write to disk.
    *   **Kernel-level Dumps:** More advanced techniques to dump memory directly from kernel mode, bypassing user-mode process monitoring.

---

### 4. Scope Definition and Environmental Considerations

The focus is a single Windows 10/11 endpoint used by a software developer. This implies:
*   The user likely has local administrator privileges or is part of a "Power Users" group, increasing the impact of credential compromise.
*   The environment may have development tools and processes that generate unusual process trees or network connections, potentially leading to false positives if baselining is not performed.
*   High likelihood of legitimate use of remote collaboration tools and scripting environments (PowerShell, Python), which can be abused by attackers.
*   The developer may interact with external repositories, cloud services, and build systems, increasing the attack surface.

**Environmental Considerations:**
*   **Baseline:** Establish a baseline of normal process execution paths, parent-child relationships, network connections (especially for known developer tools), and registry modifications to reduce false positives.
*   **Approved Software:** Maintain an inventory of approved remote access tools and ensure their legitimate usage patterns are understood.
*   **Privilege Management:** Strict enforcement of least privilege; a developer workstation should ideally not require administrative rights for daily tasks.
*   **Application Whitelisting/Control:** Implement application whitelisting (e.g., Windows Defender Application Control, AppLocker) to prevent the execution of unauthorized tools.

---

### 5. Specific Fields and Values to Monitor

**For T1219: Remote Access Software**

*   **Process Creation (Sysmon Event ID 1 / Windows Security Event ID 4688):**
    *   `Image` (contains): `anydesk.exe`, `screenconnect.client.exe`, `ateraservice.exe`, `teamviewer.exe`, `dwrcs.exe`, `connectwisecontrol.exe`.
    *   `OriginalFileName` (contains): `AnyDesk.exe`, `ScreenConnect.Client.exe`, etc. (for renamed binaries).
    *   `ParentImage` (not in whitelist of expected launchers for RA tools, e.g., browser -> RA tool installer in downloads is more suspect than an internal software distribution system).
    *   `CurrentDirectory` (not in `Program Files` or `Program Files (x86)`).
*   **Network Connection (Sysmon Event ID 3 / Windows Security Event ID 5156):**
    *   `Image` (contains): `anydesk.exe`, `screenconnect.client.exe`, etc.
    *   `DestinationPort` (is): `5938` (TeamViewer), `6568`, `7070` (AnyDesk), `8040` (ScreenConnect - default web socket), `443` (often used by many for C2, need context).
    *   `DestinationIp` (not in approved internal IP ranges and is a known external/malicious IP from threat feeds for RA tools).
*   **Registry Modification (Sysmon Event ID 12/13/14 / Windows Security Event ID 4657):**
    *   `TargetObject` (contains): `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*anydesk*`, `HKLM\SYSTEM\CurrentControlSet\Services\*anydesk*`, etc.

**For T1003.001: OS Credential Dumping: LSASS Memory**

*   **Process Access (Sysmon Event ID 10):**
    *   `TargetImage` (is): `lsass.exe`
    *   `GrantedAccess` (contains one or more of): `0x1F0FFF`, `0x1410`, `0x1000`, `0x0010` (`PROCESS_VM_READ`), `0x0400` (`PROCESS_VM_OPERATION`), `0x0008` (`PROCESS_VM_WRITE`).
    *   `SourceImage` (not in approved list for debugging/system management, e.g., `taskmgr.exe` if not explicitly authorized, or known dumping tools `mimikatz.exe`, `procdump.exe`).
*   **Process Creation (Sysmon Event ID 1 / Windows Security Event ID 4688):**
    *   `Image` (contains): `mimikatz.exe`, `procdump.exe`, `lsassdump.exe`, `out-minidump.ps1` (or similar PowerShell script names/contents).
    *   `CommandLine` (contains one or more of): `sekurlsa::logonpasswords`, `privilege::debug`, `-ma lsass.exe`, `lsass.dmp`, `get-process lsass | out-minidump`.
    *   `ParentImage` (is): `cmd.exe`, `powershell.exe`, or any non-system process, especially if the `Image` is a dumping tool.
*   **File Creation (Sysmon Event ID 11):**
    *   `TargetFilename` (ends with): `.dmp` AND `TargetFilename` (contains): `lsass`.
    *   `TargetFilename` (path not in approved temporary/dump locations for developers, if any).
*   **Module Load (Sysmon Event ID 7):**
    *   `Image` (is): `lsass.exe`
    *   `ImageLoaded` (contains): `comsvcs.dll` AND `Signed` (is): `false` or `SignatureStatus` (is): `Bad` (indicates malicious injection). Monitor for unexpected `comsvcs.dll` loads into `lsass.exe` regardless of signature status as it can be misused.