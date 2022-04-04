import "pe"
rule MAL_Mars_Stealer_Apr_2022_1 : infostealer mars
{
   meta:
        description = "Detect Mars infostealer (possible cracked version)"
        author = "Arkbird_SOLG"
        reference = "https://cert.gov.ua/article/38606"
        date = "2022-04-03"
        hash1 = "afa0662aa8eac0e607a9ffc85aa0bdfc570198dcb82dccdb40d0a459e12769dc"
        hash2 = "f67ff70f862cdcb001763c69e88434d335b185a216e2944698f20807df28bdf2"
        tlp = "white"
        adversary = "MAAS"
   strings:
        $s1 = { 8d 83 d1 01 00 00 50 e8 c4 ff ff ff 83 c4 04 50 8d 83 d1 01 00 00 50 8d 83 d1 02 00 00 50 ff d6 83 c4 0c 89 87 00 a8 01 00 8d 83 51 02 00 00 50 e8 9b ff ff ff 83 c4 04 50 8d 83 51 02 00 00 50 8d 83 d1 02 00 00 50 ff d6 83 c4 0c }
        $s2 = { 94 a1 d8 09 36 67 94 c5 f3 24 51 82 af df 0e 3d 6a 9b ca fa 27 58 85 b6 e3 15 42 73 a0 d1 fe 2e df 10 3d 6e 9b cc fa 2b 58 87 b6 e5 13 44 71 a2 cf 00 2e 5f 8c bd ea 1a 47 7a a5 d6 03 35 62 93 c0 f1 1e 4e 7d ac db 0c 3a 69 96 c7 f4 25 53 82 b1 e2 0f 3e 6c 9d ca fb 28 59 87 b8 e5 16 43 73 a0 d1 fe 2f 5c 8e bb ec 19 4a 77 a7 d4 05 32 63 91 c0 ef 1e 4d 7e ac db 0a 39 68 97 c5 f6 23 54 }
        $s3 = { 51 31 c0 8b 4c 24 08 8d 40 01 8d 49 01 80 39 00 75 f5 59 c3 60 64 a1 30 00 00 00 8b 40 0c }
        $s4 = { 27 71 79 69 6d 36 34 25 3e 00 46 57 49 4a 44 50 38 4e 56 54 34 30 32 51 43 58 59 56 33 59 37 42 30 42 33 5a 4b 00 05 6d 15 1d 2d 3e 5c 21 21 27 68 63 4b 22 37 3d 34 65 01 05 54 2f 54 6c 56 22 2e 00 55 4e 4b 00 68 74 74 70 00 00 00 00 68 74 74 70 73 00 00 00 32 30 30 00 68 74 74 70 73 3a 2f 2f }
   condition:
        uint16(0) == 0x5A4D and filesize > 40KB and all of ($s*) and 
        for any section in pe.sections : ( section.name == "LLCPPC") //YARA 4.0 +
        // legacy version
        //for any i in (0..pe.number_of_sections-1) : ( pe.sections[i].name == "LLCPPC")
}
