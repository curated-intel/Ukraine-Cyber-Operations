rule CyclopsBlink_config_identifiers
{
 meta:
 author = "NCSC"
 description = "Detects the initial characters used to identify
Cyclops Blink configuration data"
 hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
 hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
 strings:
 // Main config parameter data starts with the string "<p: "
 $ = "<p: " fullword
 // RSA public key data starts with the string "<k: "
 $ = {3C 00 3C 6B 60 00 3A 20 90 09 00 00}
 // X.509 certificate data starts with the string "<c: "
 $ = {3C 00 3C 63 60 00 3A 20 90 09 00 00}
 // RSA private key data starts with the string "<s: "
 $ = {3C 00 3C 73 60 00 3A 20 90 09 00 00}
 condition:
 (uint32(0) == 0x464c457f) and (all of them)
}
