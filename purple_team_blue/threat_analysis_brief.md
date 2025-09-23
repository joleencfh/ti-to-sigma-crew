### Threat Analysis Brief: UNC3944 TTPs on Windows 10/11 Developer Endpoint

**Target Environment:** Single Windows 10/11 endpoint used by a software developer at an energy engineering firm.

**Threat Actor:** UNC3944 (Scattered Spider) - Financially-motivated threat actor known for social engineering and use of remote access tools.

---

#### 1. Threat Classification

*   **Identified Threat Type:** Technique (behavioral aspects of an attacker's actions)
*   **Mapped MITRE ATT&CK IDs:**
    *   **T1003 OS Credential Dumping:** Adversaries may attempt to dump credentials to obtain account names and passwords for use in a current or future attack. OS credential dumping techniques are often used to steal credentials from the operating system and/or cached credentials from memory or the Registry.
        *   *Sub-Technique Focus:* T1003.001 LSASS Memory (Directly mentioned in threat intel report as "Dumping credentials from LSASS")
    *   **T1219 Remote Access Software:** Adversaries may use legitimate remote access software to maintain persistent access to systems.
        *   *Software Focus:* ScreenConnect, AnyDesk (Directly mentioned in threat intel report)
*   **Threat Severity Level:** Critical. Both T1003 and T1219 represent significant post-compromise activities that can lead to lateral movement, privileged access, and persistent control, ultimately enabling data exfiltration, ransomware deployment, and severe business disruption.

---

#### 2. Data Source Analysis

**TTP 1: T1003 OS Credential Dumping (Focus: LSASS Memory)**

*   **Optimal Log Sources for Detection:**
    *   **Endpoint Detection and Response (EDR) Logs:** High-fidelity process creation, process access, memory access, and module load events.
    *   **Sysmon Logs (Event IDs):**
        *   `Event ID 10` (ProcessAccess): Critical for detecting processes accessing `lsass.exe`.
        *   `Event ID 1` (ProcessCreate): For detecting known credential dumping tools being launched.
        *   `Event ID 3` (NetworkConnection): If tools communicate out.
        *   `Event ID 6` (DriverLoad): If kernel-mode dumping tools are used.
    *   **Windows Security Event Logs:**
        *   `Event ID 4656`, `4663` (Object Access): Auditing access to `lsass.exe` process. (Requires SACL configuration)
        *   `Event ID 4688` (Process Creation): For command-line logging of dumping tools.
*   **Required Log Fields and Event Types:**
    *   **Process Creation (Sysmon Event ID 1 / Security Event ID 4688):**
        *   `Process Name` (`Image`), `CommandLine`, `ParentProcessName` (`ParentImage`), `User` (`InitiatingProcessAccountName`), `ProcessId`, `ParentProcessId`, `OriginalFileName` (for `procdump.exe`, `mimikatz.exe`, `powershell.exe`).
    *   **Process Access (Sysmon Event ID 10 / Security Event ID 4656/4663 with SACL):**
        *   `Source Process Name` (`SourceImage`), `Source Process ID`, `Target Process Name` (`TargetImage` - specifically `lsass.exe`), `Target Process ID`, `CallTrace`, `GrantedAccess` (e.g., `0x1F0FFF` for full access, `0x1400` for `PROCESS_VM_READ`).
    *   **Module Load (EDR/Sysmon Event ID 7):**
        *   `Image`, `ImageLoaded` (for `dbghelp.dll`, `comsvcs.dll` in unusual processes).
*   **Multiple Detection Approaches:**
    *   **Signature-based (ProcessCreate):** Detect known tools (`mimikatz.exe`, `procdump.exe`) and their common command-line arguments.
    *   **Behavioral (ProcessAccess):** Detect any non-standard process (especially those without a digital signature or from unusual paths) attempting to open `lsass.exe` with `PROCESS_VM_READ` or `PROCESS_DUP_HANDLE` access. This is the most robust detection.
    *   **Behavioral (ModuleLoad):** Detect suspicious processes loading `dbghelp.dll` or `comsvcs.dll` and calling `MiniDumpWriteDump` or similar functions, particularly if the parent process is not a legitimate debugger or system utility.

**TTP 2: T1219 Remote Access Software (Focus: ScreenConnect, AnyDesk)**

*   **Optimal Log Sources for Detection:**
    *   **EDR Logs:** Process creation, network connections, file creation/modification, registry modifications, service installations.
    *   **Sysmon Logs (Event IDs):**
        *   `Event ID 1` (ProcessCreate): Detection of RAT executables.
        *   `Event ID 3` (NetworkConnection): Outbound connections to known RAT infrastructure or unusual external IP addresses/ports.
        *   `Event ID 12/13/14` (RegistryEvent): Installation artifacts, persistence mechanisms.
        *   `Event ID 11` (FileCreate): Dropping of RAT executables.
    *   **Windows Security Event Logs:**
        *   `Event ID 4688` (Process Creation): For command-line logging of RAT executables.
        *   `Event ID 5145` (Detailed File Share Access): If RATs are dropped via network shares.
    *   **Firewall/Network Proxy Logs:** Outbound connections to known RAT C2 domains/IPs, unusual ports.
*   **Required Log Fields and Event Types:**
    *   **Process Creation (Sysmon Event ID 1 / Security Event ID 4688):**
        *   `Image` (e.g., `*anydesk.exe`, `*screenconnect.client.exe`), `CommandLine`, `ParentProcessName`, `User`, `OriginalFileName`, `Hashes` (MD5, SHA256).
    *   **Network Connection (Sysmon Event ID 3 / Firewall/Proxy Logs):**
        *   `InitiatingProcessImage`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `Protocol`, `User`.
    *   **Registry Modification (Sysmon Event ID 12/13/14):**
        *   `TargetObject` (e.g., `*\Run\*`, `*\CurrentVersion\Services\*`), `Details` (Value name and data), `Image`.
    *   **File Creation (Sysmon Event ID 11 / EDR File Events):**
        *   `TargetFilename` (e.g., `C:\Program Files (x86)\AnyDesk\anydesk.exe`, `%APPDATA%\AnyDesk\*`), `Image` (Process performing the creation).
*   **Multiple Detection Approaches:**
    *   **Signature-based (ProcessCreate/FileCreate):** Detect known RAT executable names, hashes, or file paths (e.g., `anydesk.exe`, `ScreenConnect.Client.exe` in unusual locations).
    *   **Behavioral (NetworkConnection):** Detect outbound network connections from processes other than browsers to common remote access ports/protocols or known C2 infrastructure of ScreenConnect/AnyDesk (even if legitimate, flag unexpected use).
    *   **Behavioral (Registry/Service Install):** Detect unexpected installation of new services or run keys associated with remote access tools.
    *   **Baseline Deviation:** Alert on the first-time execution of such software on an endpoint, or connections to untrusted external IPs/domains.

---

#### 3. Detection Strategy

**Scope Definition:** The detection strategy is focused on a single Windows 10/11 endpoint used by a software developer. This implies a higher risk for tools and scripts, and potentially less restrictive network egress rules for developer-related traffic, requiring careful baselining.

**Environmental Considerations:**
*   **Software Developer Context:** Developers may legitimately use various tools, including some that could be repurposed by attackers (e.g., PowerShell, Python, scripting tools, legitimate remote collaboration tools). This necessitates robust behavioral detection and baselining.
*   **Energy Engineering Firm:** Implies sensitive intellectual property and operational technology exposure, increasing the criticality of effective detection.
*   **Endpoint-Centric:** Focus heavily on EDR and Sysmon for deep visibility into endpoint activities.

---

**TTP 1: T1003 OS Credential Dumping (Focus: LSASS Memory)**

*   **Detection Approach:** Primarily **Behavioral** with some **Signature-based** components.
*   **Key Indicators and Artifacts:**
    *   Unsigned or suspicious processes accessing `lsass.exe` memory.
    *   Processes like `cmd.exe`, `powershell.exe`, or non-system executables launching `procdump.exe` or `mimikatz.exe`.
    *   Creation of `.dmp` files (memory dump files) in unusual locations.
    *   Attempts to disable `LSA Protection` or `Credential Guard`.
*   **Specific Fields and Values to Monitor:**
    *   **ProcessAccess (Sysmon Event ID 10):**
        *   `TargetImage`: `lsass.exe`
        *   `GrantedAccess` contains `0x1000` (PROCESS_VM_READ) or `0x0010` (PROCESS_VM_OPERATION) or `0x0020` (PROCESS_VM_WRITE) or `0x0002` (PROCESS_DUP_HANDLE).
        *   `SourceImage`: NOT in `("C:\Windows\System32\taskmgr.exe", "C:\Windows\System32\DbgHost.exe", "C:\Windows\System32\drivers\dgagent.sys", "C:\Windows\System32\drivers\dump_atc.sys", "C:\Windows\System32\services.exe", "C:\Windows\System32\lsass.exe")`
        *   `SourceImage` is NOT digitally signed by Microsoft.
        *   `SourceImage` path is NOT a standard system directory (`C:\Windows\System32\`, `C:\Windows\SysWOW64\`).
    *   **ProcessCreate (Sysmon Event ID 1 / Security Event ID 4688):**
        *   `Image` contains `mimikatz.exe` OR `procdump.exe` OR `*lsadump*` (case-insensitive) OR `*hashdump*` (case-insensitive).
        *   `CommandLine` contains `sekurlsa::logonpasswords` OR `sekurlsa::minidump` OR `MiniDumpWriteDump` (for PowerShell).
        *   `ParentImage` is NOT a recognized legitimate administration tool or process.
    *   **FileCreate (Sysmon Event ID 11 / EDR):**
        *   `TargetFilename` ends with `.dmp` AND `Image` (creating process) is suspicious (e.g., not `taskmgr.exe`).
*   **Evasion Techniques and Variants:**
    *   **Direct System Calls / Kernel Drivers:** Bypassing user-mode hooks by directly interacting with the kernel or loading a malicious driver.
    *   **Obfuscated/In-Memory Execution:** Mimikatz variants loaded directly into memory or executed via reflectively loaded DLLs to avoid disk-based signatures.
    *   **Legitimate Tool Abuse:** Using Sysinternals ProcDump (legitimate tool) for dumping.
    *   **DLL Injection:** Injecting code into legitimate processes to perform the dump.
    *   **Mitigation:** `LSA Protection` (Credential Guard) when active significantly hinders LSASS dumping. Detection should focus on attempts to disable this feature via registry modifications (`RunAsPPL`) or other means.

---

**TTP 2: T1219 Remote Access Software (Focus: ScreenConnect, AnyDesk)**

*   **Detection Approach:** Mix of **Signature-based**, **Behavioral**, and **Statistical/Baseline** approaches.
*   **Key Indicators and Artifacts:**
    *   Execution of `AnyDesk.exe` or `ScreenConnect.Client.exe` (or similar legitimate RATs).
    *   Installation of these applications as services or via persistence mechanisms (Run keys).
    *   Outbound network connections from these processes to the internet, especially to known RAT infrastructure.
    *   Unusual or first-time execution of remote access software on the developer's endpoint.
*   **Specific Fields and Values to Monitor:**
    *   **ProcessCreate (Sysmon Event ID 1 / Security Event ID 4688):**
        *   `Image` contains `anydesk.exe` OR `screenconnect.client.exe` OR `teamviewer_desktop.exe` (if not officially sanctioned).
        *   `CommandLine` includes installation parameters (e.g., `/install`, `--install`).
        *   `ParentImage` is suspicious (e.g., `cmd.exe`, `powershell.exe` from an unexpected path, rather than a legitimate installer).
        *   `OriginalFileName` or `Description` matching known RATs.
    *   **NetworkConnection (Sysmon Event ID 3 / Firewall/Proxy Logs):**
        *   `InitiatingProcessImage` contains `anydesk.exe` OR `screenconnect.client.exe`.
        *   `DestinationPort`: `80`, `443` (often tunneled), or other specific RAT ports.
        *   `DestinationHostname` or `DestinationIp` matching known AnyDesk/ScreenConnect C2 domains/IPs (use threat intelligence feeds).
        *   `DestinationIp` is a public IP address (for unmanaged connections).
        *   **Baseline Deviation:** Monitor for connections to new or rare external IP addresses/domains from these processes.
    *   **RegistryEvent (Sysmon Event ID 12/13/14):**
        *   `TargetObject` contains `HKLM\SYSTEM\CurrentControlSet\Services\` with `DisplayName` or `ImagePath` for `AnyDesk` or `ScreenConnect` related services.
        *   `TargetObject` contains `HK*\Software\Microsoft\Windows\CurrentVersion\Run\` adding `AnyDesk.exe` or `ScreenConnect.Client.exe`.
    *   **FileCreate (Sysmon Event ID 11 / EDR):**
        *   `TargetFilename` contains `anydesk.exe` OR `screenconnect.client.exe` in unusual directories (e.g., `%APPDATA%`, `%TEMP%`, user's Downloads folder) or outside standard `Program Files`.
*   **Evasion Techniques and Variants:**
    *   **Renaming Executables:** Threat actors may rename `anydesk.exe` to blend in, requiring hash-based or behavioral detections.
    *   **Portable Mode:** Running RATs in portable mode avoids installation artifacts.
    *   **Legitimate Use Abuse:** Using existing, sanctioned remote access tools installed by IT for malicious purposes. This requires monitoring for *unusual usage patterns* (e.g., connections outside business hours, to unusual destinations, or by unusual users).
    *   **Compromised Accounts:** If an attacker gains valid credentials, their use of RATs might appear legitimate, necessitating strong authentication (MFA) and scrutiny of session details (source IP, time of day).