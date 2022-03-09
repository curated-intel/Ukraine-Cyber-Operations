rule GhostWriter_MicroLoader_72632_00001 {
meta:
author = “Cluster25”
hash1 = “e97f1d6ec1aa3f7c7973d57074d1d623833f0e9b1c1e53f81af92c057a1fdd72”
tlp = “white”
strings:
$ = “ajf09aj2.dll” fullword wide
$ = “regsvcser” fullword ascii
$ = “X l.dlT” fullword ascii
$ = “rtGso9w|4” fullword ascii
$ = “ajlj}m${<” fullword ascii
condition: (uint16(0) == 0x5a4d and all of them)
}
