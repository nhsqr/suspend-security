# Suspend security

Temporarily turns off Microsoft Defender scanning, the Windows Firewall, and SmartScreen on the PC you run it on, then puts the previous settings back after 10 or 60 minutes.

Tamper Protection cannot be turned off by this script. If it is on, the script stops and opens Windows Security so you can switch it off. When the timer ends, Tamper Protection is turned back on.

## Run

Keep both files in the same folder. Double-click `Suspend security.cmd`, or from an elevated PowerShell window:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Suspend-Security.ps1 -Minutes 10
powershell -NoProfile -ExecutionPolicy Bypass -File .\Suspend-Security.ps1 -Minutes 60
```

Leave the files where they are until the timer finishes. The restore task runs `Suspend-Security.ps1`.

## What it changes

For the timer:

- Defender real-time, behavior, download, script, and archive scanning
- Every firewall profile
- The app SmartScreen check

It does not change exclusions, accounts, BitLocker, Secure Boot, Windows Update, or LSA protection.

In the menu, choose **3** to restore immediately.
