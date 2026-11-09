; Compile with packaging/Build-Windows.ps1. Keep AppId unchanged for upgrades.
#ifndef MyAppVersion
  #define MyAppVersion "1.3.1"
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
english.CloseLanoraFailed=LANORA is still running and could not be closed. Choose Exit in the LANORA tray menu and try again.
turkish.CloseLanoraFailed=LANORA hâlâ çalışıyor ve kapatılamadı. Sistem tepsisindeki LANORA menüsünden Çıkış'ı seçip tekrar deneyin.
german.CloseLanoraFailed=LANORA läuft noch und konnte nicht beendet werden. Wählen Sie im LANORA-Menü im Infobereich Beenden und versuchen Sie es erneut.

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
  { Same name as ExitRequest.DefaultName in src/Lanora/Infrastructure/Infrastructure.cs. }
  ExitEventName = 'Local\Lanora.ExitRequest';

var
  ExitEvent: THandle;

function CreateEvent(lpEventAttributes: Integer; bManualReset, bInitialState: BOOL; lpName: string): THandle;
  external 'CreateEventW@kernel32.dll stdcall';
function SetEvent(hEvent: THandle): BOOL;
  external 'SetEvent@kernel32.dll stdcall';
function ResetEvent(hEvent: THandle): BOOL;
  external 'ResetEvent@kernel32.dll stdcall';
function CloseHandle(hObject: THandle): BOOL;
  external 'CloseHandle@kernel32.dll stdcall';

{ Number of LANORA processes (Lanora.exe, lanora.com) started from Dir; with Terminate they are stopped.
  Only this installation is affected, not a portable copy elsewhere. }
function LanoraProcesses(const Dir: string; Terminate: Boolean): Integer;
var
  Locator, Service, Procs, Proc: Variant;
  I: Integer;
  Path, Prefix: string;
begin
  Result := 0;
  Prefix := Uppercase(AddBackslash(Dir));
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Service := Locator.ConnectServer('.', 'root\CIMV2');
    Procs := Service.ExecQuery('SELECT ProcessId, ExecutablePath FROM Win32_Process WHERE Name = ''Lanora.exe'' OR Name = ''lanora.com''');
    for I := 0 to Procs.Count - 1 do
    begin
      Proc := Procs.ItemIndex(I);
      try
        Path := Proc.ExecutablePath;
      except
        Path := ''; { no access or no path }
      end;
      if (Path <> '') and (Pos(Prefix, Uppercase(Path)) = 1) then
      begin
        Result := Result + 1;
        if Terminate then
        begin
          Log('Stopping LANORA process ' + Path);
          try
            Proc.Terminate();
          except
            Log('Could not stop ' + Path + ': ' + GetExceptionMessage);
          end;
        end;
      end;
    end;
  except
    Log('LANORA process check failed: ' + GetExceptionMessage);
  end;
end;

{ True if Exe is LANORA 1.3.1 or newer, which exits by itself when ExitEvent is set. }
function KnowsExitRequest(const Exe: string): Boolean;
var
  MS, LS: Cardinal;
begin
  Result := GetVersionNumbers(Exe, MS, LS) and ((MS > $00010003) or ((MS = $00010003) and (LS >= $00010000)));
end;

{ A tray application has no window, so Windows' Restart Manager cannot close it (setup then could not replace
  Lanora.exe). Ask LANORA to exit cleanly, wait for it (a running scan is saved first), then stop what is left. }
function CloseLanora(const Dir: string): Boolean;
var
  Waited: Integer;
begin
  if ExitEvent = 0 then ExitEvent := CreateEvent(0, True, False, ExitEventName);
  if ExitEvent <> 0 then SetEvent(ExitEvent); { kept set until setup ends, so LANORA does not start meanwhile }
  if LanoraProcesses(Dir, False) = 0 then
  begin
    Result := True;
    exit;
  end;
  Log('LANORA is running; asking it to exit');
  if KnowsExitRequest(AddBackslash(Dir) + 'Lanora.exe') then
  begin
    Waited := 0;
    while (LanoraProcesses(Dir, False) > 0) and (Waited < 35000) do
    begin
      Sleep(500);
      Waited := Waited + 500;
    end;
  end;
  if LanoraProcesses(Dir, True) > 0 then Sleep(1500);
  Result := LanoraProcesses(Dir, False) = 0;
  if not Result then Log('LANORA is still running');
end;

procedure ReleaseExitEvent;
begin
  if ExitEvent <> 0 then
  begin
    ResetEvent(ExitEvent);
    CloseHandle(ExitEvent);
    ExitEvent := 0;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not CloseLanora(ExpandConstant('{app}')) then Result := CustomMessage('CloseLanoraFailed');
end;

procedure DeinitializeSetup;
begin
  ReleaseExitEvent;
end;

function InitializeUninstall: Boolean;
begin
  Result := CloseLanora(ExpandConstant('{app}'));
  if not Result then
  begin
    SuppressibleMsgBox(CustomMessage('CloseLanoraFailed'), mbError, MB_OK, IDOK);
    ReleaseExitEvent;
  end;
end;

procedure DeinitializeUninstall;
begin
  ReleaseExitEvent;
end;

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
