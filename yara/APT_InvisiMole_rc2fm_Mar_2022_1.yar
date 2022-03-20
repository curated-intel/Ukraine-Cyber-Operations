rule APT_InvisiMole_rc2fm_Mar_2022_1 : rc2fm backdoor invisimole
{
   meta:
      description = "Detect rc2fm backdoor"
      author = "Arkbird_SOLG"
      reference = "Internal Research"
      date = "2022-03-19"
      hash1 = "43b62d57fbc04026e7d63239b5d3197e10b815410f84e178052091f4ce7d0ab0"
      hash2 = "5b072f897dbae2c85bf1debb0d4e9819c7f16a31d541ebdd4e111e7160d4324e"
      hash3 = "a16b3f8aa869aebb61ae770f9701d918c4a814a4502f46a93e904d38084d23b2"
      adversary = "-"
      tlp = "white"
   strings:
      $s1 = { 48 8d 05 [2] 00 00 41 b8 ff 00 00 00 48 ba 14 00 00 00 00 00 00 00 48 89 c1 e8 [2] 00 00 c6 85 ?? f9 ff ff 00 48 8d 8d [2] ff ff ba 00 01 00 00 [4] ff [0-2] 89 85 ?? fb ff ff 48 8d 8d [2] ff ff 8b 95 ?? fb ff ff e8 [2] ff ff 4c 8d [3] 00 00 [3-4] fb ff ff [0-1] d1 ?? 48 8d [3] ff ff }
      $s2 = { 48 89 fa 48 89 53 10 c7 45 f8 00 00 00 00 48 8d 45 f8 48 89 44 24 28 44 89 6c 24 20 4c 8d 05 1a ff ff ff 49 89 d9 48 89 f1 e8 [2] ff ff 48 89 c6 48 85 f6 75 08 48 89 d9 e8 5f e3 ff ff 8b 45 f8 49 89 04 24 48 89 f0 48 8b 5d c8 48 8b 7d d0 48 8b 75 d8 4c 8b 65 e0 4c 8b 6d e8 4c 8b 75 f0 48 8d 65 00 5d c3 00 00 00 00 00 00 00 53 48 8d 64 24 e0 89 cb e8 33 fa ff ff 89 d9 e8 [2] ff ff 90 48 8d 64 24 20 5b c3 00 00 00 00 48 8d 64 24 d8 b8 00 00 00 00 89 c1 e8 [2] ff ff 90 48 8d 64 24 28 c3 00 00 00 00 00 00 00 00 48 8d 64 24 d8 e8 [2] ff ff 90 48 8d 64 24 28 c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 8d 64 24 d8 e8 [2] ff ff 90 48 8d 64 24 28 c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 8d 64 24 d8 48 8d 54 24 20 e8 [2] ff ff 84 c0 75 07 e8 [2] ff ff eb 05 b8 00 00 00 00 }
      $s3 = { 00 00 00 00 00 00 00 00 00 48 8d 64 24 d8 48 89 c8 48 8b 08 e8 [2] ff ff 90 48 8d 64 24 28 c3 00 00 00 00 00 00 00 00 00 [0-2] 48 8d 64 24 d8 [0-2] 48 89 }
      $s4 = { 48 8d 64 24 c8 48 c7 44 24 20 00 00 00 00 4c 8d 4c 24 28 e8 [2] ff ff 85 c0 75 11 e8 [2] ff ff 89 c1 83 f9 6d 74 05 e8 13 b6 ff ff 8b 44 24 28 90 48 8d 64 24 38 c3 00 00 00 00 00 00 00 00 48 8d 64 24 d8 c7 44 24 24 00 00 00 00 4c 8d 44 24 24 41 b9 02 00 00 00 48 ba 00 00 00 00 00 00 00 00 e8 [2] ff ff 89 44 24 20 81 7c 24 20 ff ff ff ff 75 15 e8 [2] ff ff 85 c0 74 0c e8 [2] ff ff 89 }
   condition:
     uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*)
}
