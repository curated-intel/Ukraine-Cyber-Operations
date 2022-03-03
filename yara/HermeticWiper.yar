rule HermeticWiper : malware {
  meta:
    description = "Hermetic Wiper loading epmntdrv.sys by resources"
    source = "Orange CD"
    date = "24/02/22"
    researcher = "Alexandre MATOUSEK"
    category = "apt"
  strings:
    $s1 = "\\\\.\\EPMNTDRV\\%u" wide fullword
    $s2 = "\\\\.\\PhysicalDrive%u" wide fullword
    $s3 = "%s%.2s" wide fullword
    $s4 = "\\\\?\\C:\\Windows\\System32\\winevt\\Logs" wide fullword
    $os1 = "DRV_XP_X86" wide fullword
    $os2 = "DRV_XP_X64" wide fullword
    $os3 = "DRV_X86" wide fullword
    $os4 = "DRV_X64" wide fullword
    $cert = /Hermetica Digital Ltd[0-1]/
  condition:
    uint16(0) == 0x5A4D and
    all of ($s*) and
    2 of ($os*) and
    $cert
}
