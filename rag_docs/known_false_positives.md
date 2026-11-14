# Known False Positives

Owner: Detection Engineering. Entries describe benign behavior that matches a detection rule. An entry applies only when every condition in it is met.

## FP-02: rundll32 Control Panel and print exports
rundll32 calling shell32 Control_RunDLL, printui PrintUIEntry, or SHCreateLocalServerRunDll from a Microsoft-signed System32 DLL is normal Windows behavior. Does not cover DLLs in user folders or rundll32 making network connections.

## FP-03: certutil -hashfile
certutil -hashfile is used by IT to verify installer checksums. It cannot download, decode, or execute content. Does not cover -urlcache, -decode, -encode, or -verifyctl.

## FP-04: OneDrive Known Folder Move
OneDrive Known Folder Move enrollment writes thousands of files in the first hour and can trigger the mass-file-modification rule. File extensions stay unchanged and no note files appear.

## FP-05: Office child processes
Office spawning C:\Windows\splwow64.exe (printing) or signed COM-automation add-in binaries from Program Files with /embedding is expected. A splwow64.exe outside C:\Windows is not covered.

## FP-06: ASP.NET dynamic compilation
w3wp.exe spawning csc.exe or cvtres.exe with Temporary ASP.NET Files arguments is ASP.NET compiling pages, usually right after an app pool recycle. w3wp.exe spawning cmd.exe or powershell.exe is never covered.

## FP-07: Windows Error Reporting and LSASS
WerFault.exe in C:\Windows\System32, launched by the WerSvc service (svchost.exe -k WerSvcGroup), accessing lsass.exe right after an Application Error event is crash reporting. Close the alert and notify the server team about the crash. Any WerFault.exe outside System32, unsigned, or launched by anything other than WerSvc is NOT covered by this entry.

## FP-09: Backup agents and vssadmin
Backup agents (Veeam, Commvault) run vssadmin list shadows, list writers, or list shadowstorage before each job. Deletion or resizing of shadow copies is never part of a normal backup job.

## FP-11: Share migration robocopy
The Share-Migration robocopy jobs run by svc_migration trigger the mass-file-modification rule until the migration completes in Q3 2026. Extensions stay unchanged and no ransom notes appear.
