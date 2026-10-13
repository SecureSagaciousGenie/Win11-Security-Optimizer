# Reinstalling apps you removed

Every app removed by the Debloat tab is reinstallable. Removal only uninstalls
the app; it doesn't blacklist it. You have three options.

## Option 1: MS Store (easiest)

1. Open the **Microsoft Store**.
2. Search for the app by name (see the table below).
3. Click **Get / Install**.

| Removed app | Search in Store for |
|-------------|---------------------|
| Xbox apps & Game Bar | `Xbox` |
| Xbox Gaming App / Game Pass | `Xbox` |
| Microsoft News (Bing News) | `Microsoft News` |
| MSN Weather (Bing Weather) | `MSN Weather` |
| Clipchamp | `Clipchamp` |
| Microsoft Solitaire Collection | `Microsoft Solitaire Collection` |
| 3D Viewer | `3D Viewer` |
| Paint 3D | `Paint 3D` |
| Mixed Reality Portal | `Mixed Reality Portal` |
| Microsoft Teams (personal) | `Microsoft Teams` |
| Get Help | `Get Help` |
| Tips | `Tips` |
| Feedback Hub | `Feedback Hub` |
| Windows Maps | `Windows Maps` |
| Sound Recorder | `Windows Sound Recorder` |
| People | `People` |
| Phone Link | `Phone Link` |
| Quick Assist | `Quick Assist` |
| Family Safety | `Microsoft Family Safety` |
| Web Search (Bing) app | `Bing` |
| Microsoft To Do | `Microsoft To Do` |

## Option 2: Reinstall ALL built-in apps at once (PowerShell)

Open an **elevated** PowerShell (Run as administrator) and run:

```powershell
Get-AppxPackage -AllUsers | ForEach-Object {
    Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue
}
```

This re-registers every inbox app that still has files staged on the system. It's
safe to run; already-installed apps are skipped.

## Option 3: Reinstall one specific app by package name

The tool logs the exact package family of everything it removes. Open the
**Restore & Logs** tab (or `%LOCALAPPDATA%\Win11SecurityOptimizer\logs\`) to find
lines like:

```
CHANGE: Removed app 'MSN Weather (Bing Weather)' (Microsoft.BingWeather_8wekyb3d8bbwe)
```

Then reinstall that one app:

```powershell
Get-AppxPackage -AllUsers -Name "Microsoft.BingWeather*" |
  ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
```

If the package was fully removed (no staged files), use the Microsoft Store
(Option 1) instead.

---

### Note on "provisioned" removal
The tool also removes the *provisioned* copy of each app so it doesn't reappear
for brand-new user accounts. Reinstalling via the Store or Option 2 restores it
for your current account normally; new accounts can also install it from the
Store.
