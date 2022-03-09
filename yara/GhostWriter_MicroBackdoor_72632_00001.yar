rule GhostWriter_MicroBackdoor_72632_00001 {
meta:
author = “Cluster25”
hash1 = “559d8e8f2c60478d1c057b46ec6be912fae7df38e89553804cc566cac46e8e91”
tlp = “white”
strings:
$ = “cmd.exe /C \”%s%s\”” fullword wide
$ = “client.dll” fullword ascii
$ = “ERROR: Unknown command” fullword ascii
$ = ” *** ERROR: Timeout occured” fullword ascii
$ = “%s\Software\Microsoft\Windows\CurrentVersion\Internet Settings” fullword ascii
$ = “MIIDazCCAlOgAwIBAgIUWOftflCclQXpmWMnL1ewj2F5Y1AwDQYJKoZIhvcNAQEL” fullword ascii
condition: (uint16(0) == 0x5a4d and all of them)
}
