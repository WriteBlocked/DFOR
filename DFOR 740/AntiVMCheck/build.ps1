param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("x64")]
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

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

    throw "MSBuild was not found. Install Visual Studio with MSBuild support."
}

function Find-VCTargetsPath {
    if ($env:VCTargetsPath -and (Test-Path $env:VCTargetsPath)) {
        return $env:VCTargetsPath
    }

    $vswhere = Find-VsWhere
    if ($vswhere) {
        $installPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
        if ($installPath) {
            $candidate = Join-Path $installPath "MSBuild\Microsoft\VC\v170\"
            if (Test-Path $candidate) { return $candidate }

            $candidate = Join-Path $installPath "MSBuild\Microsoft\VC\v160\"
            if (Test-Path $candidate) { return $candidate }
        }
    }

    return $null
}

function Test-WdkTargets {
    $vcTargetsPath = Find-VCTargetsPath
    if (-not $vcTargetsPath) {
        Write-Warning "VCTargetsPath was not found. Continuing anyway. If the build fails, run this from a Developer PowerShell for Visual Studio with the WDK installed."
        return
    }

    $driverTargets = Join-Path $vcTargetsPath "BuildCustomizations\WindowsDriver.Common.props"
    if (-not (Test-Path $driverTargets)) {
        Write-Warning "WindowsDriver.Common.props was not found at '$driverTargets'. The WDK may not be installed, or this shell is missing the proper environment."
    }
    else {
        Write-Host "Found WDK build customizations: $driverTargets"
    }
}

$msbuild = Find-MSBuild
Test-WdkTargets

& $msbuild ".\AntiVmCountermeasure.sln" "/t:Restore;Build" "/p:Configuration=$Configuration;Platform=$Platform" "/m"