<#
.SYNOPSIS
    Build, sign, and optionally install the Anti-VM-Awareness Countermeasure Platform.

.DESCRIPTION
    This script supports two workflows:

    BUILD WORKFLOW (requires Visual Studio + WDK on the build machine):
      .\build.ps1              # build and sign
      .\build.ps1 -BuildOnly   # same, explicit
      .\build.ps1 -Install     # build, sign, and install locally

    INSTALL-ONLY WORKFLOW (no build tools needed, for the target VM):
      Copy the following files to a folder on the VM:
        AvmKernel.sys, AvmMiniFilter.sys, HillerTestDriver.cer,
        AvmController.exe, AvmProbeTest.exe, build.ps1
      Then run:
        .\build.ps1 -Install

      The script auto-detects that Visual Studio is not present and
      skips the build/sign steps, using the pre-signed files in the
      current directory.

    INSTALL PREREQUISITES (on the target VM):
      - Test signing enabled:  bcdedit /set testsigning on  (reboot required)
      - Secure Boot disabled in VM/BIOS settings
      - Memory Integrity / HVCI disabled
      - Must run as Administrator

.PARAMETER Configuration
    Build configuration. Default: Release

.PARAMETER Platform
    Build platform. Default: x64

.PARAMETER CertSubject
    Subject name for the self-signed code-signing certificate.

.PARAMETER PfxPassword
    Password for the PFX file exported from the certificate.

.PARAMETER BuildOnly
    If set, only build and sign. Do not install drivers or launch controller.

.PARAMETER Install
    If set, install and start drivers. If build tools are available, builds
    first. If not, uses pre-built files from the script directory.

.PARAMETER NoLaunchController
    If set, skip launching the controller GUI after install.

.EXAMPLE
    # Build and sign (on dev machine with VS + WDK)
    .\build.ps1

.EXAMPLE
    # Build, sign, install drivers, and launch controller (dev machine)
    .\build.ps1 -Install

.EXAMPLE
    # Install pre-built drivers on target VM (no VS/WDK needed)
    .\build.ps1 -Install

.EXAMPLE
    # Build and sign only, skip install
    .\build.ps1 -BuildOnly
#>
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64",

    [string]$CertSubject = "CN=Hiller Test Driver Signing",

    [string]$PfxPassword = "TempDriverPass123!",

    [switch]$BuildOnly,

    [switch]$Install,

    [switch]$NoLaunchController
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# ---------- Detect whether we are in a full repo or a flat deploy folder ----------
$IsRepoLayout = Test-Path (Join-Path $ScriptDir "AntiVmCountermeasure.sln")

# ---------- Output paths (adapt to repo vs flat folder) ----------
if ($IsRepoLayout) {
    $KernelOutput     = Join-Path $ScriptDir "x64\$Configuration\AvmKernel.sys"
    $MiniOutput       = Join-Path $ScriptDir "x64\$Configuration\AvmMiniFilter.sys"
    $RuntimeOutput    = Join-Path $ScriptDir "x64\$Configuration\AvmRuntimeShim.dll"
    $ProbeOutput      = Join-Path $ScriptDir "x64\$Configuration\AvmProbeTest.exe"
    $ControllerOutput = Join-Path $ScriptDir "controller\AvmController\bin\$Configuration\AvmController.exe"
    $CerFile          = Join-Path $ScriptDir "HillerTestDriver.cer"
} else {
    # Flat deploy folder: all files next to the script
    $KernelOutput     = Join-Path $ScriptDir "AvmKernel.sys"
    $MiniOutput       = Join-Path $ScriptDir "AvmMiniFilter.sys"
    $RuntimeOutput    = Join-Path $ScriptDir "AvmRuntimeShim.dll"
    $ProbeOutput      = Join-Path $ScriptDir "AvmProbeTest.exe"
    $ControllerOutput = Join-Path $ScriptDir "AvmController.exe"
    $CerFile          = Join-Path $ScriptDir "HillerTestDriver.cer"
}

# ---------- Helper functions ----------
function Write-Step {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [!!] $Message" -ForegroundColor Yellow
}

function Collect-Outputs {
    Write-Step "Collecting outputs to dist\"
    $distDir = Join-Path $ScriptDir "dist"
    if (-not (Test-Path $distDir)) {
        New-Item -ItemType Directory -Path $distDir | Out-Null
    }

    $filesToCopy = @(
        $KernelOutput,
        $MiniOutput,
        $RuntimeOutput,
        $ProbeOutput,
        $ControllerOutput,
        $CerFile,
        (Join-Path $ScriptDir "build.ps1")
    )
    foreach ($f in $filesToCopy) {
        if (Test-Path $f) {
            Copy-Item $f $distDir -Force
            Write-Ok "  Copied: $(Split-Path $f -Leaf)"
        } else {
            Write-Warn "  Not found (skipped): $f"
        }
    }

    # Copy minifilter INF if present
    $miniInf = Join-Path $ScriptDir "minifilter\AvmMiniFilter\AvmMiniFilter.inf"
    if (Test-Path $miniInf) {
        Copy-Item $miniInf $distDir -Force
        Write-Ok "  Copied: AvmMiniFilter.inf"
    }
    $kernelInf = Join-Path $ScriptDir "kernel\AvmKernel\AvmKernel.inf"
    if (Test-Path $kernelInf) {
        Copy-Item $kernelInf $distDir -Force
        Write-Ok "  Copied: AvmKernel.inf"
    }

    Write-Ok "All outputs collected to: $distDir"
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run from an elevated (Administrator) PowerShell window."
    }
}

function Find-VsWhere {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"),
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\Installer\vswhere.exe")
    ) | Where-Object { $_ -and (Test-Path $_) }
    return $candidates | Select-Object -First 1
}

function Find-MSBuild {
    $vswhere = Find-VsWhere
    if ($vswhere) {
        $path = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" |
            Select-Object -First 1
        if ($path) { return $path }
    }
    $cmd = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "MSBuild was not found. Install Visual Studio 2022 with C++ desktop and WDK support."
}

function Find-SignTool {
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $searchRoots = @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"),
        (Join-Path $env:ProgramFiles "Windows Kits\10\bin")
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $searchRoots) {
        $found = Get-ChildItem -Path $root -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*\x64\*" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }

    $vswhere = Find-VsWhere
    if ($vswhere) {
        $installPath = & $vswhere -latest -products * -property installationPath
        if ($installPath) {
            $found = Get-ChildItem -Path $installPath -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
                Sort-Object FullName -Descending |
                Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }

    throw "signtool.exe was not found. Install the Windows SDK or WDK."
}

function Find-VCTargetsPath {
    if ($env:VCTargetsPath -and (Test-Path $env:VCTargetsPath)) {
        return $env:VCTargetsPath
    }
    $vswhere = Find-VsWhere
    if ($vswhere) {
        $installPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($installPath) {
            foreach ($ver in @("v170", "v160")) {
                $candidate = Join-Path $installPath "MSBuild\Microsoft\VC\$ver\"
                if (Test-Path $candidate) { return $candidate }
            }
        }
    }
    return $null
}

function Test-WdkTargets {
    $vcTargetsPath = Find-VCTargetsPath
    if (-not $vcTargetsPath) {
        Write-Warn "VCTargetsPath was not found. If the build fails, run from a Developer PowerShell with the WDK installed."
        return
    }
    $driverTargets = Join-Path $vcTargetsPath "BuildCustomizations\WindowsDriver.Common.props"
    if (-not (Test-Path $driverTargets)) {
        Write-Warn "WindowsDriver.Common.props not found at '$driverTargets'. WDK may not be installed."
    } else {
        Write-Ok "WDK build customizations found"
    }
}

function Get-TestSigningEnabled {
    try {
        $output = & bcdedit /enum 2>$null
        return ($output | Select-String -Pattern 'testsigning\s+Yes' -Quiet)
    } catch {
        return $false
    }
}

function Ensure-TestSigningReady {
    $testSigning = Get-TestSigningEnabled
    if (-not $testSigning) {
        Write-Warn "Test-signing mode is NOT enabled."
        Write-Warn "Run this command, then reboot and re-run the script:"
        Write-Warn "  bcdedit /set testsigning on"
        throw "Test-signing must be enabled before installing drivers."
    }

    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($secureBoot) {
            Write-Warn "Secure Boot is ON. Test-signed drivers will not load until Secure Boot is disabled."
        }
    } catch {
        # Secure Boot check not available on all systems
    }

    Write-Ok "Test-signing is enabled"
}

function Get-OrCreate-CodeSigningCert {
    param([string]$Subject)

    $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey } |
        Select-Object -First 1

    if (-not $cert) {
        Write-Step "Creating self-signed code-signing certificate"
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $Subject `
            -CertStoreLocation "Cert:\LocalMachine\My"
        Write-Ok "Certificate created: $($cert.Thumbprint)"
    } else {
        Write-Ok "Using existing certificate: $($cert.Thumbprint)"
    }

    return $cert
}

function Export-CodeSigningCert {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$Password
    )

    $cerPath = Join-Path $ScriptDir "HillerTestDriver.cer"
    $pfxPath = Join-Path $ScriptDir "HillerTestDriver.pfx"
    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force

    Export-Certificate -Cert $Cert.PSPath -FilePath $cerPath -Force | Out-Null
    Export-PfxCertificate -Cert $Cert.PSPath -FilePath $pfxPath -Password $securePassword -Force | Out-Null

    Write-Ok "Exported .cer and .pfx to project root"

    return @{
        Cer = $cerPath
        Pfx = $pfxPath
    }
}

function Import-LocalTrustCert {
    param([string]$CerPath)

    # Check if already imported
    $existing = Get-ChildItem Cert:\LocalMachine\TrustedPublisher -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $CertSubject }

    if (-not $existing) {
        Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Import-Certificate -FilePath $CerPath -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
        Write-Ok "Certificate imported into Root and TrustedPublisher stores"
    } else {
        Write-Ok "Certificate already in trust stores"
    }
}

function Invoke-Build {
    param([string]$MSBuildPath)

    Write-Step "Building solution ($Configuration | $Platform)"
    & $MSBuildPath ".\AntiVmCountermeasure.sln" "/t:Build" "/p:Configuration=$Configuration;Platform=$Platform" "/m" "/v:minimal"
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE"
    }
    Write-Ok "Build succeeded"
}

function Sign-Driver {
    param(
        [string]$SignToolPath,
        [string]$PfxPath,
        [string]$Password,
        [string]$DriverPath
    )

    $name = Split-Path $DriverPath -Leaf
    Write-Host "  Signing $name ..." -NoNewline
    & $SignToolPath sign /v /fd SHA256 /f $PfxPath /p $Password /ph $DriverPath 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host " FAILED" -ForegroundColor Red
        & $SignToolPath sign /v /fd SHA256 /f $PfxPath /p $Password /ph $DriverPath
        throw "Signing failed for $name"
    }
    Write-Host " OK" -ForegroundColor Green
}

function Get-MinifilterInstanceRoot {
    $buildNumber = [int](Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildNumber)
    if ($buildNumber -ge 26100) {
        return "HKLM\SYSTEM\CurrentControlSet\Services\AvmMiniFilter\Parameters\Instances"
    }
    return "HKLM\SYSTEM\CurrentControlSet\Services\AvmMiniFilter\Instances"
}

function Install-KernelDriver {
    param([string]$KernelSysPath)

    Write-Step "Installing kernel driver"

    # Stop and delete existing service first so the .sys file is unlocked
    & sc.exe stop AvmKernel 2>$null | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe delete AvmKernel 2>$null | Out-Null

    Copy-Item $KernelSysPath "C:\Windows\System32\drivers\AvmKernel.sys" -Force

    & sc.exe create AvmKernel type= kernel start= demand binPath= system32\drivers\AvmKernel.sys | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create AvmKernel service"
    }

    & sc.exe start AvmKernel | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Failed to start AvmKernel. Check Event Viewer for details."
        & sc.exe query AvmKernel
    } else {
        Write-Ok "AvmKernel service started"
    }
}

function Install-Minifilter {
    param([string]$MiniSysPath)

    Write-Step "Installing minifilter"

    # Stop and delete existing service first so the .sys file is unlocked
    & sc.exe stop AvmMiniFilter 2>$null | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe delete AvmMiniFilter 2>$null | Out-Null

    Copy-Item $MiniSysPath "C:\Windows\System32\drivers\AvmMiniFilter.sys" -Force

    & sc.exe create AvmMiniFilter type= filesys start= demand binPath= system32\drivers\AvmMiniFilter.sys group= "FSFilter Activity Monitor" depend= FltMgr | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create AvmMiniFilter service"
    }

    $instanceRoot = Get-MinifilterInstanceRoot
    Write-Host "  Using minifilter instance path: $instanceRoot"

    # Clean old entries (ignore errors if keys don't exist)
    $ErrorActionPreference = "Continue"
    & reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AvmMiniFilter\Parameters" /f 2>$null | Out-Null
    & reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\AvmMiniFilter\Instances" /f 2>$null | Out-Null
    $ErrorActionPreference = "Stop"

    & reg.exe add $instanceRoot /v DefaultInstance /t REG_SZ /d "AvmMiniFilter Instance" /f | Out-Null
    & reg.exe add "$instanceRoot\AvmMiniFilter Instance" /v Altitude /t REG_SZ /d "328766" /f | Out-Null
    & reg.exe add "$instanceRoot\AvmMiniFilter Instance" /v Flags /t REG_DWORD /d 0 /f | Out-Null

    & sc.exe start AvmMiniFilter | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Failed to start AvmMiniFilter. Check Event Viewer for details."
        & sc.exe query AvmMiniFilter
    } else {
        Write-Ok "AvmMiniFilter service started"
    }

    # Verify with fltmc
    $fltOutput = & fltmc filters 2>$null
    if ($fltOutput -match "AvmMiniFilter") {
        Write-Ok "AvmMiniFilter visible in fltmc filters"
    } else {
        Write-Warn "AvmMiniFilter not found in fltmc output"
    }
}

function Launch-Controller {
    if ($NoLaunchController) { return }

    if (-not (Test-Path $ControllerOutput)) {
        Write-Warn "Controller executable not found at $ControllerOutput"
        return
    }

    $controllerDir = Split-Path $ControllerOutput -Parent

    # Copy runtime shim next to controller if available and not already there
    if ((Test-Path $RuntimeOutput) -and ($RuntimeOutput -ne (Join-Path $controllerDir "AvmRuntimeShim.dll"))) {
        Copy-Item $RuntimeOutput (Join-Path $controllerDir "AvmRuntimeShim.dll") -Force
    }

    Write-Step "Launching controller"
    Start-Process -FilePath $ControllerOutput -WorkingDirectory $controllerDir
    Write-Ok "AvmController.exe launched"
}

# ---------- VM concealment helpers ----------

function Spoof-BiosValues {
    Write-Step "Spoofing BIOS / hardware identity values"

    $biosKey = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
    $spoofs = @{
        "BIOSVendor"           = "Dell Inc."
        "SystemManufacturer"   = "Dell Inc."
        "SystemProductName"    = "OptiPlex 7090"
        "BIOSVersion"          = "2.18.0"
        "BaseBoardManufacturer"= "Dell Inc."
        "BaseBoardProduct"     = "0XHGX6"
    }

    $ErrorActionPreference = "Continue"
    $applied = 0
    foreach ($name in $spoofs.Keys) {
        $current = (Get-ItemProperty $biosKey -Name $name -ErrorAction SilentlyContinue).$name
        if ($current) {
            Set-ItemProperty $biosKey -Name $name -Value $spoofs[$name] -ErrorAction SilentlyContinue
            if ($?) { $applied++ }
        }
    }
    $ErrorActionPreference = "Stop"

    if ($applied -gt 0) {
        Write-Ok "$applied BIOS registry values spoofed (volatile - resets on reboot)"
    } else {
        Write-Warn "Could not modify BIOS values (may require kernel-level spoofing)"
    }

    # Also spoof SystemInformation if present
    $sysInfoKey = "HKLM:\HARDWARE\DESCRIPTION\System\SystemInformation"
    if (Test-Path $sysInfoKey) {
        $ErrorActionPreference = "Continue"
        Set-ItemProperty $sysInfoKey -Name "SystemManufacturer" -Value "Dell Inc." -ErrorAction SilentlyContinue
        Set-ItemProperty $sysInfoKey -Name "SystemProductName" -Value "OptiPlex 7090" -ErrorAction SilentlyContinue
        Set-ItemProperty $sysInfoKey -Name "BIOSVersion" -Value "2.18.0" -ErrorAction SilentlyContinue
        $ErrorActionPreference = "Stop"
    }
}

function Simulate-UserActivity {
    Write-Step "Simulating user activity artifacts"

    $docs = "$env:USERPROFILE\Documents"
    $desktop = "$env:USERPROFILE\Desktop"
    $pictures = "$env:USERPROFILE\Pictures"
    $downloads = "$env:USERPROFILE\Downloads"
    $created = 0

    # Create fake documents
    $fakeFiles = @{
        "$docs\Meeting Notes - Q3 Review.txt"    = "Meeting notes from quarterly review.`nAction items:`n- Follow up on budget`n- Schedule 1:1s"
        "$docs\Project Plan Draft.txt"            = "Project timeline:`nPhase 1: Requirements gathering`nPhase 2: Development`nPhase 3: Testing"
        "$docs\Travel Expense Report.txt"         = "Trip: Denver conference`nHotel: $450`nFlight: $320`nMeals: $85"
        "$downloads\readme.txt"                   = "Downloaded installer notes"
        "$pictures\vacation_notes.txt"            = "Photos from summer trip - need to sort"
    }

    foreach ($path in $fakeFiles.Keys) {
        $dir = Split-Path $path -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        if (-not (Test-Path $path)) {
            $fakeFiles[$path] | Out-File -FilePath $path -Encoding UTF8
            $created++
            # Backdate the file to look natural
            $daysAgo = Get-Random -Minimum 7 -Maximum 90
            $ts = (Get-Date).AddDays(-$daysAgo)
            (Get-Item $path).CreationTime = $ts
            (Get-Item $path).LastWriteTime = $ts.AddHours((Get-Random -Minimum 1 -Maximum 8))
        }
    }

    # Create fake browser profile directory (Chrome)
    $chromeProfile = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    if (-not (Test-Path $chromeProfile)) {
        New-Item -ItemType Directory -Path $chromeProfile -Force | Out-Null
        # Create a minimal Preferences file so it looks like a real profile
        '{"profile":{"name":"Default"},"browser":{"has_seen_welcome_page":true}}' |
            Out-File -FilePath "$chromeProfile\Preferences" -Encoding UTF8
        $created++
    }

    # Create desktop shortcuts
    $shell = New-Object -ComObject WScript.Shell
    $shortcuts = @(
        @{ Name = "Notepad.lnk"; Target = "C:\Windows\notepad.exe" }
        @{ Name = "Calculator.lnk"; Target = "C:\Windows\System32\calc.exe" }
    )
    foreach ($sc in $shortcuts) {
        $scPath = Join-Path $desktop $sc.Name
        if (-not (Test-Path $scPath)) {
            try {
                $shortcut = $shell.CreateShortcut($scPath)
                $shortcut.TargetPath = $sc.Target
                $shortcut.Save()
                $created++
            } catch { }
        }
    }

    # Add some recent file entries
    $recentDir = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentDir) {
        foreach ($path in $fakeFiles.Keys) {
            if (Test-Path $path) {
                try {
                    $lnkPath = Join-Path $recentDir ((Split-Path $path -Leaf) + ".lnk")
                    if (-not (Test-Path $lnkPath)) {
                        $lnk = $shell.CreateShortcut($lnkPath)
                        $lnk.TargetPath = $path
                        $lnk.Save()
                    }
                } catch { }
            }
        }
    }

    Write-Ok "$created activity artifacts created"
}

function Warn-AnalysisTools {
    Write-Step "Checking for analysis tools"

    $toolProcesses = @(
        # Sysinternals
        "procmon", "procmon64", "Procmon",
        "procexp", "procexp64",
        "autoruns", "autoruns64",
        "tcpview", "tcpview64",
        "Sysmon", "Sysmon64",
        "handle", "handle64",
        "listdlls", "listdlls64",
        "vmmap", "vmmap64",
        "strings", "strings64",
        "accesschk", "accesschk64",
        # Network capture
        "wireshark", "dumpcap", "tshark",
        "fiddler", "NetworkMiner", "rawcap",
        "HttpAnalyzerStdV7", "SmartSniff",
        # Disassemblers / Decompilers
        "ida", "ida64", "idaq", "idaq64",
        "ghidra", "ghidraRun",
        "r2", "radare2", "cutter", "iaito",
        "binaryninja", "hopper",
        # Debuggers
        "x64dbg", "x32dbg", "ollydbg",
        "windbg", "kd", "cdb", "ntsd",
        "dnSpy", "dotPeek64", "ilspy",
        # PE analysis
        "pestudio", "die", "peid",
        "exeinfope", "CFF Explorer",
        "ResourceHacker",
        # API / behavior monitoring
        "apimonitor-x64", "apimonitor-x86",
        "regmon", "filemon",
        # Forensics
        "volatility", "vol",
        "autopsy", "autopsy64",
        "FTK Imager",
        "HashCalc", "hashdeep", "md5deep",
        # Hex editors
        "HxD", "010Editor", "ImHex",
        # Misc
        "Regshot", "Regshot-x64-Unicode",
        "fakenet", "inetsim",
        "yara64", "yara32",
        "ProcessHacker"
    )

    $running = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $toolProcesses -contains $_.Name }

    if ($running) {
        foreach ($proc in $running) {
            Write-Warn "Analysis tool running: $($proc.Name) (PID $($proc.Id))"
        }
        Write-Warn "These tools may allow malware to detect analysis environment"
    } else {
        Write-Ok "No common analysis tools detected"
    }
}

function Test-BuildToolsAvailable {
    try {
        $vswhere = Find-VsWhere
        if (-not $vswhere) { return $false }
        $path = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" 2>$null |
            Select-Object -First 1
        return [bool]$path
    } catch {
        return $false
    }
}

# ========================================================
# Main execution
# ========================================================
Assert-Admin

$HasBuildTools = Test-BuildToolsAvailable

# ---------- INSTALL-ONLY MODE ----------
# If -Install is set and no build tools are available, go straight to install
# using pre-signed files from the current directory.
if ($Install -and (-not $HasBuildTools)) {
    Write-Step "Install-only mode (no build tools detected)"
    Write-Host "  Using pre-built files from: $ScriptDir"

    # Verify required files exist
    $requiredFiles = @(
        @{ Path = $KernelOutput; Name = "AvmKernel.sys" },
        @{ Path = $MiniOutput;   Name = "AvmMiniFilter.sys" },
        @{ Path = $CerFile;      Name = "HillerTestDriver.cer" }
    )
    $missingFiles = @()
    foreach ($f in $requiredFiles) {
        if (-not (Test-Path $f.Path)) { $missingFiles += $f.Name }
    }
    if ($missingFiles.Count -gt 0) {
        Write-Host ""
        Write-Host "  Missing required files:" -ForegroundColor Red
        foreach ($m in $missingFiles) {
            Write-Host "    - $m" -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "  Copy these files from the build machine into this folder:" -ForegroundColor Yellow
        Write-Host "    AvmKernel.sys, AvmMiniFilter.sys, HillerTestDriver.cer" -ForegroundColor Yellow
        Write-Host "    AvmController.exe (optional, for GUI)" -ForegroundColor Yellow
        Write-Host "    AvmProbeTest.exe  (optional, for validation)" -ForegroundColor Yellow
        throw "Required files missing for install. See above."
    }
    Write-Ok "Required driver files found"

    # Verify test signing
    Ensure-TestSigningReady

    # Import certificate to trust stores
    Write-Step "Importing certificate"
    Import-LocalTrustCert -CerPath $CerFile

    # Install drivers
    Install-KernelDriver -KernelSysPath $KernelOutput
    Install-Minifilter -MiniSysPath $MiniOutput

    # System-level VM concealment
    Spoof-BiosValues
    Simulate-UserActivity
    Warn-AnalysisTools

    # Launch controller
    Launch-Controller

    Write-Step "Install complete"
    Write-Host ""
    Write-Host "  Kernel driver:  INSTALLED"
    Write-Host "  Minifilter:     INSTALLED"
    if (Test-Path $ControllerOutput) {
        Write-Host "  Controller:     $(if ($NoLaunchController) {'AVAILABLE'} else {'LAUNCHED'})"
    }
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. In the controller, click Refresh to verify both drivers are connected"
    Write-Host "  2. Set mode to Full Concealment and click Apply Policy"
    Write-Host "  3. Run AvmProbeTest.exe to validate concealment"
    Write-Host ""
    Write-Host "To uninstall:"
    Write-Host "  sc.exe stop AvmMiniFilter; sc.exe stop AvmKernel"
    Write-Host "  sc.exe delete AvmMiniFilter; sc.exe delete AvmKernel"
    exit 0
}

# ---------- BUILD WORKFLOW ----------
# Requires Visual Studio + WDK

if (-not $HasBuildTools) {
    Write-Host ""
    Write-Host "ERROR: Visual Studio / MSBuild not found." -ForegroundColor Red
    Write-Host ""
    Write-Host "  To BUILD: install Visual Studio 2022 with C++ desktop tools and the WDK." -ForegroundColor Yellow
    Write-Host "  To INSTALL pre-built drivers: run  .\build.ps1 -Install" -ForegroundColor Yellow
    Write-Host ""
    throw "Build tools not found. Use -Install for install-only mode on target VMs."
}

Write-Step "Checking build environment"
$msbuild = Find-MSBuild
Write-Ok "MSBuild: $msbuild"
Test-WdkTargets

# Build
Invoke-Build -MSBuildPath $msbuild

# Verify outputs
$missingFiles = @()
foreach ($f in @($KernelOutput, $MiniOutput, $ControllerOutput)) {
    if (-not (Test-Path $f)) { $missingFiles += $f }
}
if ($missingFiles.Count -gt 0) {
    throw "Build succeeded but expected outputs are missing:`n$($missingFiles -join "`n")"
}
Write-Ok "All expected build outputs present"

# Sign drivers
Write-Step "Signing drivers"
$signtool = Find-SignTool
Write-Ok "SignTool: $signtool"

$cert = Get-OrCreate-CodeSigningCert -Subject $CertSubject
$certPaths = Export-CodeSigningCert -Cert $cert -Password $PfxPassword

Sign-Driver -SignToolPath $signtool -PfxPath $certPaths.Pfx -Password $PfxPassword -DriverPath $KernelOutput
Sign-Driver -SignToolPath $signtool -PfxPath $certPaths.Pfx -Password $PfxPassword -DriverPath $MiniOutput

if ($BuildOnly -or (-not $Install)) {
    Write-Step "Build and sign complete"
    Collect-Outputs
    Write-Host ""
    Write-Host "Signed outputs and deployment package in: $(Join-Path $ScriptDir 'dist')"
    Write-Host ""
    Write-Host "To deploy to a VM, copy the dist\ folder to the VM,"
    Write-Host "then run:  .\build.ps1 -Install"
    exit 0
}

# Install mode (with build tools available — build+sign already done above)
Write-Step "Preparing for driver installation"
Ensure-TestSigningReady
Import-LocalTrustCert -CerPath $certPaths.Cer

Install-KernelDriver -KernelSysPath $KernelOutput
Install-Minifilter -MiniSysPath $MiniOutput

# System-level VM concealment
Spoof-BiosValues
Simulate-UserActivity
Warn-AnalysisTools

Launch-Controller

Write-Step "Setup complete"
Write-Host ""
Write-Host "  Kernel driver:  INSTALLED"
Write-Host "  Minifilter:     INSTALLED"
Write-Host "  Controller:     $(if ($NoLaunchController) {'AVAILABLE'} else {'LAUNCHED'})"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. In the controller, click Refresh to verify both drivers are connected"
Write-Host "  2. Set mode to Full Concealment and click Apply Policy"
Write-Host "  3. Run AvmProbeTest.exe to validate concealment"
Write-Host ""
Write-Host "To uninstall:"
Write-Host "  sc.exe stop AvmMiniFilter; sc.exe stop AvmKernel"
Write-Host "  sc.exe delete AvmMiniFilter; sc.exe delete AvmKernel"