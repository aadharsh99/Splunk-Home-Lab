# Detection Rule Documentation

## Detection 01 — SMB Enumeration Detected

**Purpose:** Detect suspicious `whoami.exe` discovery activity using Sysmon Event ID 1 process creation telemetry.

**Telemetry:** Sysmon — Event ID 1, Process Create.

**Key fields**
- `Image`
- `CommandLine`
- `ParentImage`
- `User`
- Host
- Timestamp

**Observed evidence**

Sysmon Event ID 1 records:

```text
Image: C:\Windows\System32\whoami.exe
CommandLine: whoami /all
ParentImage: C:\Windows\System32\cmd.exe
User: WINDOWS-10\vboxuser
```

Splunk extracts the process and command-line fields to support investigation.

**Representative SPL**

```spl
index=main whoami.exe
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='User'>(?<User>[^<]+)</Data>"
| table _time host Image CommandLine ParentImage User
```

**Alert:** `Suspicious Whoami Discovery Activity`

**Evidence basis:** the available Sysmon evidence shows `whoami.exe` executing `whoami /all` with `cmd.exe` as the parent process. The detection is therefore documented as Whoami discovery activity, not confirmed PowerShell execution.

**Recommended refinement**

Use separate detections for:
1. `whoami.exe` discovery activity.
2. Review the process tree to determine whether `powershell.exe` actually launched the discovery command.
3. Suspicious parent-child process relationships.

This prevents false ATT&CK attribution and improves analyst confidence.
