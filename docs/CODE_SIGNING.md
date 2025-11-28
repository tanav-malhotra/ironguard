# Code Signing Guide for ironguard

This guide explains how to sign the ironguard binary to avoid Windows SmartScreen warnings and antivirus false positives during CyberPatriot competitions.

## Why Sign Your Binary?

1. **Windows SmartScreen**: Unsigned executables trigger "Windows protected your PC" warnings
2. **Antivirus Software**: Many AV solutions flag unsigned binaries as suspicious
3. **Competition Day**: You don't want to waste time dealing with false positives

## Option 1: Self-Signed Certificate (Free, Quick)

### Step 1: Create a Self-Signed Certificate

```powershell
# Run PowerShell as Administrator
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=IronGuard CyberPatriot Tool" -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(3)

# Export the certificate (you'll need this for the competition machine)
$pwd = ConvertTo-SecureString -String "YourPassword123!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "ironguard-signing.pfx" -Password $pwd
```

### Step 2: Sign the Binary

```powershell
# Sign the executable
$cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath "ironguard.exe" -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
```

### Step 3: Verify the Signature

```powershell
Get-AuthenticodeSignature -FilePath "ironguard.exe"
```

## Option 2: Using signtool.exe (Windows SDK)

### Prerequisites
1. Install Windows SDK: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
2. signtool.exe is in: `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\`

### Sign with PFX Certificate

```batch
signtool sign /f ironguard-signing.pfx /p YourPassword123! /t http://timestamp.digicert.com /fd SHA256 ironguard.exe
```

### Verify

```batch
signtool verify /pa /v ironguard.exe
```

## Option 3: Free Code Signing Certificate (SignPath)

For open-source projects, SignPath offers free code signing:
1. Apply at https://signpath.io/
2. They provide certificates trusted by Windows
3. Best option for avoiding SmartScreen entirely

## Competition Day Procedure

### Before the Competition

1. **Build the binary** on your development machine
2. **Sign it** using one of the methods above
3. **Verify the signature** works
4. **Test on a clean Windows VM** to ensure no SmartScreen warnings

### On Competition Day

If you're bringing a pre-signed binary:

```powershell
# Verify the signature is intact
Get-AuthenticodeSignature -FilePath "ironguard.exe"

# Should show: SignerCertificate with your certificate info
# Status should be: Valid
```

### If SmartScreen Still Triggers

1. **Click "More info"** → "Run anyway"
2. Or right-click → Properties → Unblock → Apply
3. Or add to Windows Defender exclusions:
   ```powershell
   Add-MpPreference -ExclusionPath "C:\path\to\ironguard.exe"
   ```

## Building with Embedded Manifest

Add a Windows manifest to your Go build for better compatibility:

### Create `ironguard.manifest`

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="amd64"
    name="IronGuard"
    type="win32"
  />
  <description>CyberPatriot AI Assistant</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/> <!-- Windows 10 -->
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/> <!-- Windows 8.1 -->
    </application>
  </compatibility>
</assembly>
```

### Create `ironguard.rc`

```
1 24 "ironguard.manifest"
1 ICON "ironguard.ico"
```

### Build with Resource

```bash
# Install rsrc tool
go install github.com/akavel/rsrc@latest

# Generate syso file
rsrc -manifest ironguard.manifest -ico ironguard.ico -o rsrc.syso

# Build (rsrc.syso will be automatically included)
go build -ldflags="-s -w" -o ironguard.exe ./cmd/ironguard
```

## Hash Verification

Always verify your binary's hash to ensure it wasn't tampered with:

### Generate Hash

```powershell
Get-FileHash -Path ironguard.exe -Algorithm SHA256 | Select-Object Hash
```

### Create a verification file

```
ironguard.exe SHA256: ABC123...
Built: 2024-01-15
Signed by: CN=IronGuard CyberPatriot Tool
```

## Troubleshooting

### "Publisher: Unknown publisher"
- Your certificate isn't trusted by Windows
- Self-signed certs will always show this
- Consider SignPath for a trusted certificate

### "Windows Defender SmartScreen prevented an unrecognized app"
1. Click "More info"
2. Click "Run anyway"
3. Or add to exclusions

### Antivirus Quarantine
1. Add to exclusions BEFORE running
2. Or temporarily disable AV (not recommended in competition)
3. Submit to AV vendor as false positive

### Signature Invalid After Transfer
- File may have been modified
- Re-download or re-sign
- Check file integrity with hash

## Quick Reference Commands

```powershell
# Create self-signed cert
New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=IronGuard" -CertStoreLocation "Cert:\CurrentUser\My"

# Sign
Set-AuthenticodeSignature -FilePath "ironguard.exe" -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)

# Verify
Get-AuthenticodeSignature -FilePath "ironguard.exe"

# Hash
Get-FileHash -Path ironguard.exe -Algorithm SHA256
```

## Notes for Competition

1. **Bring multiple copies**: USB, cloud storage, etc.
2. **Test on competition-like VMs** before the day
3. **Have a backup plan**: Know how to bypass SmartScreen
4. **Document your binary**: Hash, signature, build date
5. **Keep the signing certificate**: You may need to re-sign

