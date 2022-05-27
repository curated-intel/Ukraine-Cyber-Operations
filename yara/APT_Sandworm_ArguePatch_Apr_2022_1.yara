rule APT_Sandworm_ArguePatch_Apr_2022_1 : apt arguepatch loader sandworm
{
   meta:
        description = "Detect ArguePatch loader used by Sandworm group for load CaddyWiper"
        author = "Arkbird_SOLG"
        reference = "https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/"
        date = "2022-04-30"
        updated = "2022-05-20"
        // -> https://twitter.com/ESETresearch/status/152753172690540953
        hash1 = "8f096e3b5ecd2aca35794a85f8b76093b3968a8737e87e8008710b4014c779e3"
        hash2 = "cda9310715b7a12f47b7c134260d5ff9200c147fc1d05f030e507e57e3582327"
        hash3 = "750cbba9a36859b978bfe5f082be44815027bc74dc2728210abbcba828ce6f56"
        tlp = "white"
        adversary = "Sandworm"
        level = "Fully Experimental" // not tested in HA, some trouble are reported in the Yara submission
   strings:
        $s1 = { 8b 41 ?? 83 f8 09 77 41 ff 24 85 [3] 00 6a 00 e8 ?? 01 00 00 c3 6a 01 eb f6 6a 08 eb f2 6a 01 6a 00 e8 7c 00 00 00 c3 6a 01 6a 0a eb f4 6a 00 6a 08 eb ee 6a 00 eb f2 6a 00 6a 10 eb e4 e9 30 00 00 00 e9 ?? ff ff ff }
        $s2 = { 6a 14 68 [3] 00 e8 [2] 00 00 6a 01 e8 [4] 59 84 c0 0f 84 ?? 01 00 00 32 db 88 5d e7 83 65 fc 00 e8 [4] 88 45 dc a1 [3] 00 33 c9 41 3b c1 0f 84 ?? 01 00 00 85 c0 75 49 89 0d [3] 00 68 [3] 00 68 [3] 00 e8 [3] 00 59 59 85 c0 74 11 c7 45 fc fe ff ff ff b8 ff 00 00 00 e9 ?? 00 00 00 68 [3] 00 68 [3] 00 e8 [3] 00 59 59 c7 05 [3] 00 02 }
        $s3 = { 83 ec 08 0f ae 5c 24 04 8b 44 24 04 25 80 7f 00 00 3d 80 1f 00 00 75 0f d9 3c 24 66 8b 04 24 66 83 e0 7f 66 83 f8 7f 8d 64 24 08 0f 85 [2] 00 00 eb 00 f3 0f 7e 44 24 04 66 0f 28 15 [3] 00 66 0f 28 c8 66 0f 28 f8 66 0f 73 d0 34 66 0f 7e c0 66 0f 54 05 [3] 00 66 0f fa d0 66 0f d3 ca a9 00 08 00 00 74 4c 3d ff 0b 00 00 7c 7d 66 0f f3 ca 3d 32 0c 00 00 7f 0b 66 0f d6 4c 24 04 dd }
        $s4 = { 8d a4 24 00 00 00 00 8d a4 24 00 00 00 00 90 c6 85 70 ff ff ff fe 32 ed d9 ea de c9 e8 2b 01 00 00 d9 e8 de c1 f6 85 61 ff ff ff 01 74 04 d9 e8 de f1 f6 c2 40 75 02 d9 fd 0a ed 74 02 d9 e0 e9 cf 02 00 00 e8 46 01 00 00 0b c0 74 14 32 ed 83 f8 02 74 02 f6 d5 d9 c9 d9 e1 eb a0 e9 eb 02 00 00 e9 a9 03 00 00 dd d8 dd d8 db 2d [3] 00 c6 85 70 ff ff ff }
   condition:
        uint16(0) == 0x5a4d and filesize > 60KB and all of ($s*)
}
