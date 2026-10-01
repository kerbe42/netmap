; Inno Setup script for the SubnetSleuth installer.
;   iscc /DAppVersion=<version> packaging\subnetsleuth.iss      (after pyinstaller packaging\subnetsleuth-gui.spec)
; CI passes the version read from subnetsleuth/__init__.py; the output is dist\SubnetSleuth-<version>-setup.exe.
; Installs per user by default (no administrator rights needed: %LOCALAPPDATA%\Programs\SubnetSleuth),
; adds a Start menu entry, optionally a desktop shortcut and the .sleuth file association.
;
; SubnetSleuth was called NetMap up to 0.12. The AppId is unchanged, so this installer upgrades a
; NetMap install in place: it installs into the SubnetSleuth folder, removes the old NetMap program
; folder and shortcuts, and points .netmap files at SubnetSleuth too. Settings and saved credentials
; (HKCU\Software\netmap) are left alone; the app copies them to its own key on first start.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{5E0C3A5B-7F7B-4B8E-9C1E-2D6A4F0B9E31}
AppName=SubnetSleuth
AppVersion={#AppVersion}
AppVerName=SubnetSleuth {#AppVersion}
AppPublisher=kerbe42
AppPublisherURL=https://github.com/kerbe42/subnetsleuth
AppSupportURL=https://github.com/kerbe42/subnetsleuth/issues
AppUpdatesURL=https://github.com/kerbe42/subnetsleuth/releases
DefaultDirName={autopf}\SubnetSleuth
DefaultGroupName=SubnetSleuth
UsePreviousAppDir=no
UsePreviousGroup=no
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=SubnetSleuth-{#AppVersion}-setup
SetupIconFile=subnetsleuth.ico
UninstallDisplayIcon={app}\SubnetSleuth.exe
UninstallDisplayName=SubnetSleuth {#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesAssociations=yes
CloseApplications=yes

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked
Name: "association"; Description: "Open .sleuth (and older .netmap) project files with SubnetSleuth"; GroupDescription: "Files:"

[InstallDelete]
; PyInstaller puts every library under _internal, and file names change between versions.
; Clear it before copying the new build so an upgrade cannot leave stale DLLs or Qt plugins behind.
Type: filesandordirs; Name: "{app}\_internal"
; NetMap, as this app was called up to 0.12: its program folder and shortcuts
Type: filesandordirs; Name: "{autopf}\NetMap"
Type: filesandordirs; Name: "{autoprograms}\NetMap"
Type: files; Name: "{autodesktop}\NetMap.lnk"

[Files]
Source: "..\dist\SubnetSleuth\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\SubnetSleuth"; Filename: "{app}\SubnetSleuth.exe"
Name: "{group}\SubnetSleuth command line"; Filename: "{cmd}"; Parameters: "/k ""{app}\subnetsleuth-cli.exe"" --help"; WorkingDir: "{userdocs}"
Name: "{autodesktop}\SubnetSleuth"; Filename: "{app}\SubnetSleuth.exe"; Tasks: desktopicon

[Registry]
Root: HKA; Subkey: "Software\Classes\.sleuth"; ValueType: string; ValueName: ""; ValueData: "SubnetSleuth.Project"; Flags: uninsdeletevalue; Tasks: association
Root: HKA; Subkey: "Software\Classes\.netmap"; ValueType: string; ValueName: ""; ValueData: "SubnetSleuth.Project"; Flags: uninsdeletevalue; Tasks: association
Root: HKA; Subkey: "Software\Classes\NetMap.Project"; ValueType: none; Flags: deletekey
Root: HKA; Subkey: "Software\Classes\SubnetSleuth.Project"; ValueType: string; ValueName: ""; ValueData: "SubnetSleuth project"; Flags: uninsdeletekey; Tasks: association
Root: HKA; Subkey: "Software\Classes\SubnetSleuth.Project\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\SubnetSleuth.exe,0"; Tasks: association
Root: HKA; Subkey: "Software\Classes\SubnetSleuth.Project\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\SubnetSleuth.exe"" ""%1"""; Tasks: association

[UninstallDelete]
; The log folder (%LOCALAPPDATA%\SubnetSleuth\subnetsleuth.log and rotations). Project files are wherever the user saved them and are never touched.
Type: filesandordirs; Name: "{localappdata}\SubnetSleuth"
Type: filesandordirs; Name: "{localappdata}\NetMap"

[Run]
Filename: "{app}\SubnetSleuth.exe"; Description: "Start SubnetSleuth"; Flags: nowait postinstall skipifsilent

[Code]
// Settings (window layout, preferences, encrypted SNMP credentials) live under
// HKCU\Software\subnetsleuth, and under HKCU\Software\netmap from before the rename. They
// survive an upgrade; on uninstall the user is asked, so a reinstall can keep them and a clean
// removal really is clean.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    if RegKeyExists(HKEY_CURRENT_USER, 'Software\subnetsleuth') or RegKeyExists(HKEY_CURRENT_USER, 'Software\netmap') then
    begin
      if UninstallSilent or
         (MsgBox('Also remove your SubnetSleuth settings and saved credentials (HKCU\Software\subnetsleuth, and HKCU\Software\netmap from NetMap)?',
                 mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then
      begin
        RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'Software\subnetsleuth');
        RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'Software\netmap');
      end;
    end;
  end;
end;
