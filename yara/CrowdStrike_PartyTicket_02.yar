rule CrowdStrike_PartyTicket_02 : PartyTicket golang 
{
    meta:
        copyright = "(c) 2022 CrowdStrike Inc."
        description = "Detects Golang-based PartyTicket ransomware"
        version = "202202250130"
        last_modified = "2022-02-25"
      strings:
        $s1 = "voteFor403"
        $s2 = "highWay60"
        $s3 = "randomiseDuration"
        $s4 = "subscribeNewPartyMember"
        $s5 = "primaryElectionProces"
        $s6 = "baggageGatherings"
        $s7 = "getBoo"
        $s8 = "selfElect"
        $s9 = "wHiteHousE"
        $s10 = "encryptedJB"
        $goid = { ff 20 47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 71 62 30 48 37 41 64 57 41 59 44 7a 66 4d 41 31 4a 38 30 42 2f 6e 4a 39 46 46 38 66 75 70 4a 6c 34 71 6e 45 34 57 76 41 35 2f 50 57 6b 77 45 4a 66 4b 55 72 52 62 59 4e 35 39 5f 4a 62 61 2f 32 6f 30 56 49 79 76 71 49 4e 46 62 4c 73 44 73 46 79 4c 32 22 0a 20 ff }
        $pdb = "C://projects//403forBiden//wHiteHousE"
    condition:
        (uint32(0) == 0x464c457f or (uint16(0) == 0x5a4d and uint16(uint32(0x3c)) == 0x4550)) and 4 of ($s*) or $pdb or $goid
}
