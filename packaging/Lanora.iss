; Compile with packaging/Build-Windows.ps1. Keep AppId unchanged for upgrades.
#ifndef MyAppVersion
  #define MyAppVersion "1.2.1"
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
; The "lanora" command is added to the user's PATH; open consoles are notified of the change.
ChangesEnvironment=yes
#ifdef EnableSigning
SignTool=lanora
SignedUninstaller=yes
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[CustomMessages]
english.AddToPath=Use the "lanora" command in Command Prompt and PowerShell (adds LANORA to PATH)
turkish.AddToPath="lanora" komutunu Komut İstemi ve PowerShell'de kullan (LANORA'yı PATH'e ekler)
german.AddToPath=Befehl "lanora" in Eingabeaufforderung und PowerShell verwenden (fügt LANORA zu PATH hinzu)
english.CommandLine=Command line:
turkish.CommandLine=Komut satırı:
german.CommandLine=Befehlszeile:

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "{cm:AddToPath}"; GroupDescription: "{cm:CommandLine}"

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\LANORA"; Filename: "{app}\Lanora.exe"
Name: "{autodesktop}\LANORA"; Filename: "{app}\Lanora.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Lanora.exe"; Description: "{cm:LaunchProgram,LANORA}"; Flags: nowait postinstall skipifsilent

; Deliberately keep %LOCALAPPDATA%\Lanora (history, backups, logs) on uninstall.

[Code]
const
  EnvironmentKey = 'Environment';

{ Position of Dir as one entry of ";Paths;" (case-insensitive), 0 if it is not there. }
function PathEntryPos(Paths, Dir: string): Integer;
begin
  Result := Pos(';' + Uppercase(RemoveBackslashUnlessRoot(Dir)) + ';', ';' + Uppercase(Paths) + ';');
end;

procedure AddToUserPath(Dir: string);
var
  Paths: string;
begin
  if not RegQueryStringValue(HKCU, EnvironmentKey, 'Path', Paths) then Paths := '';
  if PathEntryPos(Paths, Dir) > 0 then exit;
  if (Paths <> '') and (Copy(Paths, Length(Paths), 1) <> ';') then Paths := Paths + ';';
  RegWriteExpandStringValue(HKCU, EnvironmentKey, 'Path', Paths + RemoveBackslashUnlessRoot(Dir));
end;

procedure RemoveFromUserPath(Dir: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKCU, EnvironmentKey, 'Path', Paths) then exit;
  P := PathEntryPos(Paths, Dir);
  if P = 0 then exit;
  { Remove ";Dir" from ";Paths;" and drop the helper semicolons again. }
  Paths := ';' + Paths + ';';
  Delete(Paths, P, Length(RemoveBackslashUnlessRoot(Dir)) + 1);
  Paths := Copy(Paths, 2, Length(Paths) - 2);
  RegWriteExpandStringValue(HKCU, EnvironmentKey, 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('addtopath') then AddToUserPath(ExpandConstant('{app}'))
    else RemoveFromUserPath(ExpandConstant('{app}'));
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then RemoveFromUserPath(ExpandConstant('{app}'));
end;
