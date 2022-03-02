rule CyclopsBlink_handle_mod_0xf_command
{
 meta:
 author = "NCSC"
 description = "Detects the code bytes used to check module ID 0xf
control flags and a format string used for file content upload"
 hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
 hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
 strings:
 // Tests execute flag (bit 0)
 $ = {54 00 06 3E 54 00 07 FE 54 00 06 3E 2F 80 00 00}
 // Tests add module flag (bit 1)
 $ = {54 00 06 3E 54 00 07 BC 2F 80 00 00}
 // Tests run as shellcode flag (bit 2)
 $ = {54 00 06 3E 54 00 07 7A 2F 80 00 00}
 // Tests upload flag (bit 4)
 $ = {54 00 06 3E 54 00 06 F6 2F 80 00 00}
 // Upload format string
 $ = "file:%s\n" fullword
 condition:
 (uint32(0) == 0x464c457f) and (all of them)
}
