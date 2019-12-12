#x64
$Filename = (Get-Location).Path + "\RunasCs_net2_x64.exe"
$base64string_x64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileName))
$base64string_x64 | Out-File RunasCs.base64

#x86
$Filename = (Get-Location).Path + ".\RunasCs_net2_x86.exe"
$base64string_x86 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileName))
$base64string_x86 | Out-File RunasCs_x86.base64