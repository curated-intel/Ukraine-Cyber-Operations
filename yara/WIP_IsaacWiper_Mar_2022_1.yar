rule WIP_IsaacWiper_Mar_2022_1 : wiper isaacwiper
{
   meta:
        description = "Detect the IsaacWiper wiper"
        author = "Arkbird_SOLG"
        reference = "https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/"
        date = "2022-03-03"
        hash1 = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
        hash2 = "7bcd4ec18fc4a56db30e0aaebd44e2988f98f7b5d8c14f6689f650b4f11e16c0"
        tlp = "White"
        adversary = "-"
   strings:
        $s1 = { 6b c2 68 8d 8c 24 98 01 00 00 42 89 94 24 28 0c 00 00 ba 68 00 00 00 6a 68 53 03 c8 e8 1f 5e 00 00 8b bc 24 30 0c 00 00 8d 8c 24 a0 01 00 00 83 c4 08 4f 6b c7 68 6a 00 6a 00 89 44 24 34 03 c1 50 68 20 35 00 10 6a 00 6a 00 ff 15 48 60 02 10 89 44 24 28 85 c0 74 36 8b 84 24 98 0c 00 00 8d 8c 24 30 0c 00 00 6a 04 ba 04 00 00 00 8d 0c 81 40 89 84 24 9c 0c 00 00 8d 44 24 2c 50 e8 be 5d 00 00 8b 94 24 30 0c 00 00 83 c4 08 eb 4c 8b 94 24 28 0c 00 00 8d 42 ff 3b f8 74 36 2b d7 8d 8c 24 98 01 00 00 8b 7c 24 2c 03 cf 6b c2 68 ba 90 0a 00 00 2b d7 83 e8 68 50 8d 84 24 04 02 00 00 03 c7 50 e8 78 5d 00 00 8b 94 24 30 0c 00 00 83 c4 08 4a 89 94 24 28 0c }
        $s2 = { 8b 43 10 6a 08 8b 40 04 c7 44 03 10 d8 27 03 10 8b 43 10 8b 48 04 8d 41 f8 89 44 0b 0c 8b 03 8b 40 04 c7 04 03 c0 27 03 10 8b 03 8b 48 04 8d 41 e0 89 44 19 fc 8b 03 8b 40 04 c7 04 03 d0 27 03 10 8b 03 8b 48 04 8d 41 88 89 44 19 fc c7 07 50 28 03 10 e8 35 4d 00 00 83 c4 04 8b f0 6a 01 e8 ac 41 00 00 89 46 04 8d 5f 24 89 77 34 8d 47 08 89 5f 2c 8d 4f 14 89 47 10 8d 57 18 c7 07 04 28 03 10 8d 77 04 c6 47 48 00 8d 5f 28 c6 47 3e 00 83 c4 04 89 77 0c 89 4f 1c 89 57 20 89 5f 30 c7 00 00 00 00 00 a1 44 6c 03 10 c7 02 00 00 00 00 c7 03 00 00 00 00 c7 06 00 00 00 00 c7 01 00 00 00 00 c7 47 24 00 00 00 00 6a 40 89 47 40 a1 48 6c 03 10 6a 02 68 60 24 03 10 c7 47 4c 00 00 00 00 89 47 44 c7 47 38 00 00 00 00 e8 c3 }
        $s3 = { ff 75 0c 8b ce ff 75 08 ff 15 6c 61 02 10 ff d6 eb 14 6a 00 ff 75 0c ff 75 08 ff 15 24 61 02 10 50 }
        $s4 = { 83 7e 24 07 0f 57 c0 66 0f 13 45 e4 66 0f 13 45 f4 75 16 6a 00 8d 45 e4 50 8d 45 f4 50 56 ff 15 0c 60 02 10 83 }
   condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
