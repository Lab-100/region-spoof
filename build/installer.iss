; Region Spoof — инсталлятор (Inno Setup 7)
; Сборка: ISCC.exe build\installer.iss

#define MyAppName "Region Spoof"
#define MyAppVersion "1.2-alpha"
#define MyAppPublisher "Lab-100"
#define MyAppExeName "RegionSpoof.exe"
#define MyAppId "405AE587-75F5-450A-B3B4-A3DA604D74EF"

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL=https://github.com/Lab-100/region-spoof
AppSupportURL=https://github.com/Lab-100/region-spoof
AppUpdatesURL=https://github.com/Lab-100/region-spoof
DefaultDirName={autopf}\RegionSpoof
DefaultGroupName=Region Spoof
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\out
OutputBaseFilename=RegionSpoof-{#MyAppVersion}-Setup
SetupIconFile=..\build\app.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
VersionInfoVersion=1.2.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=Region Spoof Applet (альфа)
LicenseFile=..\LICENSE.txt
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "Russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "English"; MessagesFile: "compiler:Default.isl"

[Messages]
Russian.LauncherUninstallerAppRunning=Для корректного удаления закройте Region Spoof и нажмите «Далее».
UninstallAppRunningExitMessage=Приложение запущено. Закройте его и повторите удаление.

[InstallDelete]
Type: filesandordirs; Name: "{localappdata}\RegionSpoof\run"
Type: filesandordirs; Name: "{localappdata}\RegionSpoof\logs"

[Files]
Source: "..\dist\RegionSpoof\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\dist\RegionSpoof\pb2.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\Region Spoof"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autoprograms}\Region Spoof\Region Spoof"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autoprograms}\Region Spoof\Справка (README)"; Filename: "{app}\docs\README.md"
Name: "{autoprograms}\Region Spoof\Удалить Region Spoof"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Запустить Region Spoof"; Flags: nowait postinstall skipifsilent