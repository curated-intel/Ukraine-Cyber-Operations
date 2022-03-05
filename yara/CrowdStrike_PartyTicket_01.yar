rule CrowdStrike_PartyTicket_01 : ransomware golang 
{
    meta:
        copyright = "(c) 2022 CrowdStrike Inc."
        description = "Detects Golang-based crypter"
        version = "202202250130"
        last_modified = "2022-02-25"
    strings:
        $ = ".encryptedJB" ascii
        $start = { ff 20 47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 }
        $end = { 0a 20 ff }
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
        for 1 of ($end) : ( @start < @ and @start + 1024 > @) and
        all of them
}
