; Inno Setup script for the NetMap installer.
;   iscc /DAppVersion=0.3.0 packaging\netmap.iss      (after pyinstaller packaging\netmap-gui.spec)
; Installs per user by default (no administrator rights needed: %LOCALAPPDATA%\Programs\NetMap),
; adds a Start menu entry, optionally a desktop shortcut and the .netmap file association.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{5E0C3A5B-7F7B-4B8E-9C1E-2D6A4F0B9E31}
AppName=NetMap
AppVersion={#AppVersion}
AppVerName=NetMap {#AppVersion}
AppPublisher=kerbe42
AppPublisherURL=https://github.com/kerbe42/netmap
AppSupportURL=https://github.com/kerbe42/netmap/issues
AppUpdatesURL=https://github.com/kerbe42/netmap/releases
DefaultDirName={autopf}\NetMap
DefaultGroupName=NetMap
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=NetMap-{#AppVersion}-setup
SetupIconFile=netmap.ico
UninstallDisplayIcon={app}\NetMap.exe
UninstallDisplayName=NetMap {#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesAssociations=yes
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "association"; Description: "Open .netmap project files with NetMap"; GroupDescription: "Files:"

[Files]
Source: "..\dist\NetMap\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NetMap"; Filename: "{app}\NetMap.exe"
Name: "{group}\NetMap command line"; Filename: "{cmd}"; Parameters: "/k ""{app}\netmap-cli.exe"" --help"; WorkingDir: "{userdocs}"
Name: "{autodesktop}\NetMap"; Filename: "{app}\NetMap.exe"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "Software\Classes\.netmap"; ValueType: string; ValueName: ""; ValueData: "NetMap.Project"; Flags: uninsdeletevalue; Tasks: association
Root: HKA; Subkey: "Software\Classes\NetMap.Project"; ValueType: string; ValueName: ""; ValueData: "NetMap project"; Flags: uninsdeletekey; Tasks: association
Root: HKA; Subkey: "Software\Classes\NetMap.Project\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\NetMap.exe,0"; Tasks: association
Root: HKA; Subkey: "Software\Classes\NetMap.Project\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\NetMap.exe"" ""%1"""; Tasks: association

[Run]
Filename: "{app}\NetMap.exe"; Description: "Start NetMap"; Flags: nowait postinstall skipifsilent
