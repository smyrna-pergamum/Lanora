# LANORA — icon, Windows installer and GitHub

This package is based on the 1.2.0 source code. No changes were made to the
scanning engine. The icon and distribution preparation were added. The Windows
installer has not yet been verified by running it; the package does not include
a prebuilt installer EXE.

## 1. Icon

The interface's dark green `#173C33`, primary green `#2D7659` and light green
`#C6EEA3` are used. The shield represents security; the three dots joined in a
check-mark shape represent observing the network. The existing SVG brand
language is preserved.

In `src/Lanora/Assets/`:

- `Lanora.svg`: editable vector source.
- `Lanora.png`: 1024 × 1024 PNG with a transparent background.
- `Lanora.ico`: 16, 20, 24, 32, 40, 48, 64, 96, 128 and 256 pixel layers.

The icon is linked to the EXE resources and the system tray; the browser
favicon, side menu and About section use the same graphic. It takes effect once
the new EXE is built. Windows may show the old icon from its cache; check the
new build in a different folder. The compiled EXE from the previous ZIP is not
part of this source package.

## 2. Building the Windows installer

Install the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) and
[Inno Setup](https://jrsoftware.org/isdl.php) on Windows. Keep Inno Setup's
preprocessor component. Extract the ZIP and open PowerShell in the `Lanora`
folder that contains `Lanora.slnx`:

```powershell
dotnet test Lanora.slnx -c Debug
node tests/frontend/frontend-checks.cjs
.\packaging\Build-Windows.ps1
```

The frontend check requires Node.js. The build script does not run the tests
itself; if the first two commands report errors, fix them first. If PowerShell
blocks the downloaded file, review its contents and then unblock only this
project's script from the file's Properties; do not turn off global security
settings.

The outputs are in `dist/installer/`:

| File | Use |
|---|---|
| `Lanora-1.2.0-Setup-x64.exe` | Setup wizard, Start menu entry, optional desktop shortcut and uninstaller |
| `Lanora-1.2.0-Portable-x64.zip` | Use without installation |
| `SHA256SUMS.txt` | SHA-256 values of the downloadable files |

The installer installs per user and does not require administrator rights. The
user does not need .NET installed separately. The install location is
`%LOCALAPPDATA%\Programs\Lanora` and the data location is `%LOCALAPPDATA%\Lanora`.
Uninstalling does not delete user data. Before updating or uninstalling, exit
the application from the system tray menu. For later releases, change the
Version in the `.csproj`; keep the AppId in `Lanora.iss` unchanged.

This is a **Setup.exe** solution. If an MSI is specifically required for
enterprise deployment, the same publish output must be packaged as an MSI with
a tool such as WiX Toolset. Changing the file extension does not convert it.
The provided script does not produce an MSI.

## 3. "Unknown publisher" and SmartScreen

Building an installer does not verify the publisher's identity. That requires a
**code signing** identity from a trusted provider; a website TLS certificate is
not sufficient for this purpose.

- A valid Authenticode signature provides a verified publisher name on Windows.
- The SmartScreen "Windows protected your PC" warning also takes file/publisher
  reputation into account. It may appear even for a new, signed release.
- A self-created certificate does not solve the trust problem for the general
  public.
- An EV certificate no longer guarantees that SmartScreen is bypassed
  automatically.
- Use a consistent publisher identity for every release; add a timestamp and
  do not modify the EXE after signing.

There are two options:

**Certificate store / token / HSM:** Prepare a validated code signing
certificate and SignTool from the Windows SDK. Then:

```powershell
.\packaging\Build-Windows.ps1 `
  -Publisher 'YOUR VERIFIED PUBLISHER NAME' `
  -CertificateThumbprint 'CERTIFICATE_THUMBPRINT' `
  -SignToolPath 'C:\Program Files (x86)\Windows Kits\10\bin\SDK_VERSION\x64\signtool.exe'
```

The certificate must be in the user's Personal/My store and its private key in
its provider. The script first signs the application, then signs the
uninstaller and the installer through Inno Setup. No real certificate is
included in this package.

**Microsoft Artifact Signing:** Set up an Azure account, authentication and a
Public Trust certificate profile; use the official SignTool/Actions
integration. Eligible organizations in EU countries such as Germany can apply.
As of 20 October 2026, Public Trust applications from individual developers are
limited to the USA/Canada. Verify eligibility before purchasing a subscription.
The certificate store script in this package does not configure Azure signing
automatically.

Signing order: build the application → sign the application → produce the
signed uninstaller and installer → verify the installer signature → publish the
final files.

## 4. Uploading the source code to GitHub

First decide whether the source code will be public or private. If you share it
as open source, add the license of your choice. Keep `THIRD-PARTY-NOTICES.md`.
Complete the license texts and the notices for distributed dependencies before
a public release.

1. Create a new, empty `Lanora` repository on GitHub. Since a README and
   gitignore already exist, do not add them again when creating it.
2. Make the folder containing `Lanora.slnx` the repository root. Upload the
   `.github/` folder as well.
3. Run the following commands in a terminal with Git installed. Replace
   `YOUR_USERNAME`:

```powershell
git init
git branch -M main
git add .
git status
git commit -m "Prepare LANORA 1.2.0 distribution"
git remote add origin https://github.com/YOUR_USERNAME/Lanora.git
git push -u origin main
```

The `git status` output should contain only the sources you intend to share. Do
not upload databases, user scan results, logs, tokens, private keys or
certificate passwords. `.gitignore` excludes `bin/`, `obj/`, `dist/`, databases
and private key extensions. `.gitignore` does not retroactively remove files
that were already added to Git. If you already have a Git repository, check the
existing origin instead of repeating the `init/remote add` steps. Use Git
Credential Manager or GitHub CLI for the GitHub session; do not write a
password or token into a source file.

## 5. Building Setup.exe on GitHub

If you do not want to build on your Windows computer, use the included workflow:

1. Open the **Actions** tab of the repository.
2. Select the **Windows installer (unsigned)** workflow.
3. Click **Run workflow**.
4. Download the `Lanora-Windows-unsigned` archive from the **Artifacts**
   section of the successfully completed run.

The workflow runs the C# and frontend tests on Windows, builds the EXE and
creates the installer with Inno Setup. Outputs are kept for 14 days. This
workflow produces **unsigned** files; a signing identity must be set up
separately. The workflow has read-only permissions and does not publish a
public Release on its own.

## 6. Publishing the release users will download

The source code lives in the Git repository; the executables live in the
**Releases** section.

1. On GitHub, select **Releases → Draft a new release**.
2. Select/create the tag `v1.2.0` with `main` as the target.
3. Enter `LANORA 1.2.0` as the title and add the changes and the Windows x64
   requirement.
4. Attach the generated Setup.exe, Portable ZIP and `SHA256SUMS.txt`.
5. If you use signing, upload the final, verified signed files. Do not attach
   certificate keys. If it is an unsigned beta, state this clearly in the
   release notes.
6. Test download, installation, first launch, tray icon, scan/report, upgrade
   and uninstall on a clean Windows 11 computer; then select **Publish
   release**.

If you only want to distribute downloads, you do not have to make the source
code public; you can use Releases in a separate distribution repository that
contains no sensitive sources. GitHub Pages does not run a Windows application;
it can serve as a download/landing page.

## Verified during preparation

- Windows x64 Release build: 0 errors, 0 warnings.
- Self-contained Windows x64 publish: successful; icon resources included.
- JavaScript syntax and the existing 10 frontend checks: passed.
- The existing 74 C# tests in a separate Linux-compatible test copy: passed.
  The desktop entry point was excluded; local test fonts were used for the PDF
  tests.
- The Windows tray, install/uninstall, a real signing provider and a GitHub
  workflow run were not tested in this environment. This work is not a new
  security audit.

## Official resources

- [.NET single-file deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview)
- [Inno Setup](https://jrsoftware.org/isdl.php)
- [Inno Setup signing](https://jrsoftware.org/ishelp/topic_setup_signtool.htm)
- [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- [SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- [Artifact Signing setup/eligibility](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)
- [Adding locally hosted code to GitHub](https://docs.github.com/get-started/importing-your-projects-to-github/importing-source-code-to-github/adding-locally-hosted-code-to-github)
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
