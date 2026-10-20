; Compile with packaging/Build-Windows.ps1. Keep AppId unchanged for upgrades.
#ifndef MyAppVersion
  #define MyAppVersion "1.2.0"
#endif
#ifndef PublishDir
  #define PublishDir AddBackslash(SourcePath) + "..\dist\Lanora-" + MyAppVersion + "-win-x64"
#endif
#ifndef InstallerDir
  #define InstallerDir AddBackslash(SourcePath) + "..\dist\installer"
#endif
#ifndef MyAppPublisher
  #define MyAppPublisher "LANORA"
#endif

[Setup]
AppId={{44232662-8756-4C64-8709-85BA0D38CF11}
AppName=LANORA
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\Lanora
DefaultGroupName=LANORA
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#InstallerDir}
OutputBaseFilename=Lanora-{#MyAppVersion}-Setup-x64
SetupIconFile=..\src\Lanora\Assets\Lanora.ico
UninstallDisplayIcon={app}\Lanora.exe
Compression=lzma2/normal
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
#ifdef EnableSigning
SignTool=lanora
SignedUninstaller=yes
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\LANORA"; Filename: "{app}\Lanora.exe"
Name: "{autodesktop}\LANORA"; Filename: "{app}\Lanora.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Lanora.exe"; Description: "{cm:LaunchProgram,LANORA}"; Flags: nowait postinstall skipifsilent

; Deliberately keep %LOCALAPPDATA%\Lanora (history, backups, logs) on uninstall.
