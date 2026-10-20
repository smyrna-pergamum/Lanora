# Windows distribution

Run commands from the repository root (the folder containing `Lanora.slnx`).
Install [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) and
[Inno Setup with its preprocessor](https://jrsoftware.org/isdl.php) on Windows.

```powershell
.\packaging\Build-Windows.ps1
```

The script reads the version from the project, publishes a self-contained x64
application and creates these files in `dist/installer/`:

- `Lanora-1.2.0-Setup-x64.exe`: a per-user installer with Start menu entry,
  optional desktop shortcut and uninstall entry.
- `Lanora-1.2.0-Portable-x64.zip`: the same published app without an installer.
- `SHA256SUMS.txt`: SHA-256 checksums of those two files.

No .NET installation is required on the user's machine. Close LANORA through
its tray menu before upgrading or uninstalling. User data in
`%LOCALAPPDATA%\Lanora` is retained on uninstall. The application is installed
in `%LOCALAPPDATA%\Programs\Lanora`; installation requires no administrator rights.
Keep the AppId in `Lanora.iss` constant for future upgrades. Change the project
version for each release. The script does not run tests; run `dotnet test` and
the frontend checks before a local release. The supplied GitHub workflow runs both.

## Optional signing with a certificate provider

An unsigned installer can be tested, but is not a signed public release.
A trusted public code-signing identity is needed for the verified publisher
name in Windows. A self-signed certificate is suitable only for environments
that explicitly trust it; it does not solve trust for public downloads.

With a valid code-signing certificate accessible in the current user's
Personal certificate store (including its token/HSM provider) and Windows SDK
SignTool installed, run:

```powershell
.\packaging\Build-Windows.ps1 `
  -Publisher 'YOUR VERIFIED PUBLISHER NAME' `
  -CertificateThumbprint 'YOUR_CERTIFICATE_THUMBPRINT' `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\YOUR_SDK_VERSION\x64\signtool.exe' `
  -TimestampUrl 'http://timestamp.digicert.com'
```

Use your provider's recommended RFC 3161 timestamp URL if different. No private
key file or password is stored in this project. The script signs the application
first, then configures Inno Setup to sign the uninstaller and the installer.
SignTool verifies the application and installer signatures; timestamps use SHA256.
The Inno signing hook uses a process-scoped PowerShell execution-policy option
to run the local helper. It does not change Windows security settings.

Microsoft Artifact Signing is a separate cloud-signing path. The included
certificate-store helper does **not** configure Azure signing. After identity
validation, use Microsoft's official integration instead, and arrange the same
sequence: publish → sign app → package and sign uninstaller/setup → verify.
An eligible EU organization can apply for Public Trust signing. At the time of
preparation, individual-developer Public Trust enrollment is limited to the US
and Canada; check current eligibility before subscribing.

A valid signature shows the verified publisher; SmartScreen also considers
file and publisher reputation, so a new signed release can still trigger a
warning. Creating an MSI instead of an EXE does not provide a signing identity.
Do not edit an executable after signing. The workflow included here deliberately
produces **unsigned** artifacts and does not configure signing credentials.

## MSI alternative

If a deployment team specifically requires MSI, use WiX Toolset or an MSI
packaging product to package the same `dotnet publish` output. An Inno Setup
EXE is not an MSI and renaming it does not convert it. Keep product upgrade
identity stable, increment the package version, configure x64/per-user or
per-machine installation deliberately, and sign both the app and the MSI.
This repository provides an Inno Setup recipe, not a validated MSI project.

## GitHub workflow

Push this source tree with `Lanora.slnx`, `src/`, `tests/`, `packaging/` and
`.github/` at the repository root. In GitHub choose:
**Actions → Windows installer (unsigned) → Run workflow**.
After a successful run, download `Lanora-Windows-unsigned` from **Artifacts**.
Its files can then be attached manually to a GitHub Release. The workflow does
not publish a release, change repository contents or access signing credentials.
It has read-only repository permission and retains build artifacts for 14 days.

## Validation scope

The preparation environment cross-compiled and published the Windows x64 app
with no warnings or errors. JavaScript syntax and all 10 supplied frontend
checks passed. All 74 supplied C# tests passed in a separate Linux-compatible
harness (desktop entry point excluded; local test fonts used). These tests do
not exercise the Windows tray, installer or signature provider.

The installer script and GitHub workflow require their first Windows run.
Before a public release, use a clean Windows 11 machine to check installation,
first launch, tray icon, scan/report, upgrade, uninstall, and signature status.
This is distribution preparation, not a new security audit or a claim that the
entire application was validated on Windows.

## Primary references (checked 2026-10-20)

- [.NET single-file publishing](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview)
- [Inno Setup downloads](https://jrsoftware.org/isdl.php)
- [Inno Setup icon](https://jrsoftware.org/ishelp/topic_setup_setupiconfile.htm)
- [Inno Setup signing](https://jrsoftware.org/ishelp/topic_setup_signtool.htm)
- [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- [SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- [Artifact Signing setup and eligibility](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)
- [GitHub: add local source](https://docs.github.com/get-started/importing-your-projects-to-github/importing-source-code-to-github/adding-locally-hosted-code-to-github)
- [GitHub: manage releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
