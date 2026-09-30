; Inno Setup script for the NetMap installer.
;   iscc /DAppVersion=<version> packaging\netmap.iss      (after pyinstaller packaging\netmap-gui.spec)
; CI passes the version read from netmap/__init__.py; the output is dist\NetMap-<version>-setup.exe.
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

[InstallDelete]
; PyInstaller puts every library under _internal, and file names change between versions.
; Clear it before copying the new build so an upgrade cannot leave stale DLLs or Qt plugins behind.
Type: filesandordirs; Name: "{app}\_internal"

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

[UninstallDelete]
; The log folder (%LOCALAPPDATA%\NetMap\netmap.log and rotations). Project files are wherever the user saved them and are never touched.
Type: filesandordirs; Name: "{localappdata}\NetMap"

[Run]
Filename: "{app}\NetMap.exe"; Description: "Start NetMap"; Flags: nowait postinstall skipifsilent

[Code]
// Settings (window layout, preferences, encrypted SNMP credentials) live under
// HKCU\Software\netmap. They survive an upgrade; on uninstall the user is asked,
// so a reinstall can keep them and a clean removal really is clean.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if RegKeyExists(HKEY_CURRENT_USER, 'Software\netmap') then
    begin
      if UninstallSilent or
         (MsgBox('Also remove your NetMap settings and saved credentials (HKCU\Software\netmap)?',
                 mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
        RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'Software\netmap');
    end;
  end;
end;
