rule APT_Sandworm_Cyclops_Blink_Mar_2022_1 : backdoor cyclopsblink x86
{
   meta:
      description = "Detect Cyclops Blink backdoor used by Sandworm group"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/nicastronaut/status/1503772915711496198?s=21"
      date = "2022-03-15"
      hash1 = "145bf0e879d544a17364c53e1e695adab8e927fe196cc0d21ad14be3e2cb469f"
      hash2 = "3830213049d64b09f637563faa470b0f2edd0034aa9e92f7908374bd1d6df116"
      hash3 = "cc3d51578a9dcc7e955061881490e54883904956f5ca5ee2918cd3b249415e59"
      adversary = "SandWorm"
   strings:
      $s1 = { 69 70 74 61 62 6c 65 73 20 2d ?? 20 25 73 20 2d 70 20 74 63 70 20 2d 2d 64 70 6f 72 74 20 25 64 20 2d 6a 20 41 43 43 45 50 54 20 26 3e 2f 64 65 76 2f 6e 75 6c 6c }
      $s2 = { 7c 08 03 a6 83 61 00 2c 83 81 00 30 83 a1 00 34 83 c1 00 38 83 e1 00 3c 38 21 00 40 4e 80 00 20 80 01 00 44 3b 60 00 00 7f 63 db 78 83 21 00 24 83 41 00 28 7c 08 03 a6 83 61 00 2c 83 81 00 30 83 a1 00 34 83 c1 00 38 83 e1 00 3c 38 21 00 40 4e 80 00 20 80 1f 00 20 2f 80 00 00 41 9e 00 24 7f a3 eb 78 38 9f }
      $s3 = { 93 bf 00 20 91 7f 00 14 7c 08 03 a6 91 7d 00 30 91 7d 00 00 83 e1 00 1c 83 a1 00 14 38 21 00 20 4e 80 00 20 80 01 00 24 39 40 00 00 7d 43 53 78 83 a1 00 14 83 }
      $s4 = { 43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 62 61 73 65 36 34 25 73 }
      $s5 = { 50 52 45 52 4f 55 54 49 4e 47 00 [0-1] 49 4e 50 55 54 00 [0-2] 46 4f 52 57 41 52 44 00 4f 55 54 50 55 54 00 [0-1] 50 4f 53 54 52 4f 55 54 49 4e 47 }
      $s6 = { 63 6f 6e 66 69 67 ( 64 2d 68 61 73 68 2e 78 6d 6c | 2d 20 3c 63 6d 64 3e 20 3c 61 72 67 3e )  }
   condition:
      uint32(0) == 0x464C457F and filesize > 30KB and 4 of ($s*)
}
