param(
    [Parameter(Mandatory = $true)][string]$Canary,
    [Parameter(Mandatory = $true)][string]$RunDir,
    [Parameter(Mandatory = $true)][string]$ExitCode
)

Add-Type -AssemblyName System.Windows.Forms | Out-Null

$text = @"
Trident side-load canary ran.

Canary
$Canary

Folder
$RunDir

Host
$RunDir\where.exe

DLL
$RunDir\version.dll

Marker
$RunDir\where.dat

where.exe exit code: $ExitCode
"@

[System.Windows.Forms.MessageBox]::Show(
    $text,
    "LAB-TRIDENT-SIDELOAD",
    [System.Windows.Forms.MessageBoxButtons]::OK,
    [System.Windows.Forms.MessageBoxIcon]::Information
) | Out-Null
