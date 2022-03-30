rule caddywiper {
  meta:
  author = "Ali Mosajjal"
  email = "hi@n0p.me"
  license = "Apache 2.0"
  description = "Caddy Wiper Stack String Detection"

  strings:
    $s1 = /F.{6}i.{6}n.{6}d.{6}F.{6}i.{6}r.{6}s.{6}t.{6}F.{6}i.{6}l.{6}e.{6}A/      // FindFirstFileA
    $s2 = /F.{6}i.{6}n.{6}d.{6}N.{6}e.{6}x.{6}t.{6}F.{6}i.{6}l.{6}e.{6}A/           // FindNextFileA
    $s3 = /C.{6}r.{6}e.{6}a.{6}t.{6}e.{6}F.{6}i.{6}l.{6}e.{6}A/                     // CreateFileA
    $s4 = /G.{6}e.{6}t.{6}F.{6}i.{6}l.{6}e.{6}S.{6}i.{6}z.{6}e/                     // GetFileSize
    $s5 = /L.{6}o.{6}c.{6}a.{6}l.{6}A.{6}l.{6}l.{6}o.{6}c/                          // LocalAlloc
    $s6 = /S.{6}e.{6}t.{6}F.{6}i.{6}l.{6}e.{6}P.{6}o.{6}i.{6}n.{6}t.{6}e.{6}r/      // SetFilePointer
    $s7 = /W.{3}r.{3}i.{3}t.{3}e.{3}F.{3}i.{3}l.{3}e/                               // WriteFile
    $s8 = /L.{6}o.{6}c.{6}a.{6}l.{6}F.{6}r.{6}e.{6}e/                               // LocalFree
    $s9 = /C.{6}l.{6}o.{6}s.{6}e.{6}H.{6}a.{6}n.{6}d.{6}l.{6}e/                     // CloseHandle
    $s10 = /F.{3}i.{3}n.{3}d.{3}C.{3}l.{3}o.{3}s.{3}e/                              // FindClose
  condition:
    all of ($s*) and filesize < 100KB
}
