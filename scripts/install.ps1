$banner = @"
██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
"@
Write-Host $banner

# Admin check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "This installer must be run as Administrator."
  exit 1
}

$repo = $env:IRONGUARD_REPO
if (-not $repo -or $repo.Trim() -eq "") { $repo = "tanav-malhotra/ironguard" }
$api = "https://api.github.com/repos/$repo/releases/latest"
$arch = (Get-CimInstance Win32_Processor).AddressWidth
if ($arch -eq 64) {
  $assetArch = "x86_64"
} else {
  Write-Error "Unsupported arch: $arch"
  exit 1
}
$assetOs = "windows"

Write-Host "[*] Fetching latest release metadata..."
$meta = Invoke-RestMethod -Uri $api -UseBasicParsing
$asset = $meta.assets | Where-Object { $_.browser_download_url -match "$assetOs-$assetArch" } | Select-Object -First 1
if (-not $asset) { Write-Error "Could not find release asset for $assetOs-$assetArch"; exit 1 }

$temp = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath() + [System.Guid]::NewGuid().ToString()) -Force
try {
  $assetPath = Join-Path $temp.FullName "asset.bin"
  Write-Host "[*] Downloading $($asset.browser_download_url)"
  Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $assetPath -UseBasicParsing
  $dest = "${env:ProgramFiles}\Ironguard"
  New-Item -ItemType Directory -Path $dest -Force | Out-Null
  # If the asset is a zip, expand; else assume raw exe
  if ($asset.browser_download_url -match "\.zip$") {
    Write-Host "[*] Unpacking zip..."
    $zip = $assetPath
    Expand-Archive -LiteralPath $zip -DestinationPath $temp -Force
    $src = Get-ChildItem -Path $temp -Recurse -File | Where-Object { $_.Name -match "^ironguard.*\.exe$" } | Select-Object -First 1
    if (-not $src) { $src = Get-ChildItem -Path $temp -Recurse -File | Where-Object { $_.Extension -eq ".exe" } | Select-Object -First 1 }
    if (-not $src) { Write-Error "Could not locate ironguard executable in archive."; exit 1 }
    Copy-Item -Path $src.FullName -Destination (Join-Path $dest "ironguard.exe") -Force
  } else {
    Copy-Item -Path $assetPath -Destination (Join-Path $dest "ironguard.exe") -Force
  }

  # Add to PATH if needed
  $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  if ($currentPath -notmatch [Regex]::Escape($dest)) {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$dest", "Machine")
    Write-Host "[*] PATH updated. You may need to open a new terminal."
  }

  Write-Host "[*] Verifying..."
  & (Join-Path $dest "ironguard.exe") --help | Out-Host
  Write-Host "[+] Done. Run 'ironguard init' next."
}
finally {
  Remove-Item -Path $temp.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
