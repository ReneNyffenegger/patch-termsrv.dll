#
#   Get status of the two services UmRdpService and TermService...
#
$svc_UmRdpService_status = (get-service UmRdpService).status
$svc_TermService_status  = (get-service TermService ).status

#
#   ... display them ...
#
write-host "Status of service UmRdpService: $svc_TermService_status"
write-host "Status of service TermService:  $svc_TermService_status"

#
#   ... before stopping them ...
stop-service UmRdpService
stop-service TermService

#
#   Save ACL and owner of termsrv.dll:
#
$termsrv_dll_acl   = get-acl c:\windows\system32\termsrv.dll
$termsrv_dll_owner = $termsrv_dll_acl.owner
write-host "Owner of termsrv.dll:           $termsrv_dll_owner"

#
#   Create backup of termsrv.dll, just in case:
#
copy-item    c:\windows\system32\termsrv.dll c:\windows\system32\termsrv.dll.copy

#
#   Take ownership of the DLL...
#
takeown   /f c:\windows\system32\termsrv.dll

$new_termsrv_dll_owner = (get-acl c:\windows\system32\termsrv.dll).owner

#
#    ... and grant (/G) full control (:F) to myself:
#
# cacls c:\windows\system32\termsrv.dll /G $new_termsrv_dll_owner:F
cacls c:\windows\system32\termsrv.dll /G rene:F


#
#   Read DLL as byte-array in order to modify the bytes.
#
#   See https://stackoverflow.com/a/57342311/180275 for some details.
#
# $dll_as_bytes = get-content c:\windows\system32\termsrv.dll -raw -asByteStream    # PowerShell Core version
  $dll_as_bytes = get-content c:\windows\system32\termsrv.dll -raw -encoding byte   # PowerShell traditional version

#
#   Convert the byte array to a string that represents each byte's value
#   as hexadecimal value, separated by spaces:
#
$dll_as_text = $dll_as_bytes.forEach('ToString', 'X2') -join ' '

#
#   Search for byte array (which is dependent on the Windows edition) and replace them.
#   See
#      http://woshub.com/how-to-allow-multiple-rdp-sessions-in-windows-10/
#   for details.
#
# $dll_as_text_replaced = $dll_as_text -replace '39 81 3C 06 00 00 0F 84 5D 61 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' # Windows 1909
  $dll_as_text_replaced = $dll_as_text -replace '39 81 3C 06 00 00 0F 84 5D 61 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' # Windows 1903
# $dll_as_text_replaced = $dll_as_text -replace '39 81 3C 06 00 00 0F 84 3B 2B 01 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' # Windows 1809
# $dll_as_text_replaced = $dll_as_text -replace '8B 99 3C 06 00 00 8B B9 38 06 00 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' # Windows 1803
# $dll_as_text_replaced = $dll_as_text -replace '8B 99 3C 06 00 00 8B B9 38 06 00 00', 'B8 00 01 00 00 89 81 38 06 00 00 90' # Windows 1803


#
#   Use the replaced string to create a byte array again
#
# [byte[]] $dll_as_bytes_replaced = -split $dll_as_text_replaced -replace '^', '0x' # PowerShell Core version
  [byte[]] $dll_as_bytes_replaced = -split $dll_as_text_replaced -replace '^', '0x' # PoserShell traditional version

#
#   Create termsrv.dll.patched from byte array:
#
set-content c:\windows\system32\termsrv.dll.patched -encoding byte -Value $dll_as_bytes_replaced

#
#   Compare patched and original DLL (/b: binary comparison)
#
fc.exe /b c:\windows\system32\termsrv.dll.patched c:\windows\system32\termsrv.dll
#
#   Expected output something like:
#
#       0001F215: B8 39
#       0001F216: 00 81
#       0001F217: 01 3C
#       0001F218: 00 06
#       0001F21A: 89 00
#       0001F21B: 81 0F
#       0001F21C: 38 84
#       0001F21D: 06 5D
#       0001F21E: 00 61
#       0001F21F: 00 01
#       0001F220: 90 00
#

#
#   Overwrite original DLL with patched version:
#
copy-item c:\windows\system32\termsrv.dll.patched c:\windows\system32\termsrv.dll

#
#   Restore original ACL:
#
set-acl c:\windows\system32\termsrv.dll $termsrv_dll_acl

#
#   Start services again:
#
# start-service UmRdpService
# start-service TermService
sc start TermService
sc start UmRdpService
