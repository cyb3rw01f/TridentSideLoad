param(
    [Parameter(Mandatory = $true)][string]$HostPath,
    [Parameter(Mandatory = $true)][string]$DllPath
)
$h = Get-AuthenticodeSignature -FilePath $HostPath
$d = Get-AuthenticodeSignature -FilePath $DllPath
Write-Output ("where.exe  " + $h.Status + "  " + $h.SignerCertificate.Subject)
Write-Output ("version.dll  " + $d.Status)
