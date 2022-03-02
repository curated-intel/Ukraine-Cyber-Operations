rule MAL_PARTY_TICKET {
    meta:
      desc = "PartyTicket Golang Ransomware - associated with HermeticWiper campaign"
      author = "Hegel @ SentinelLabs"
      version = "1.0"
      last_modified = "02.24.2022"
      hash = "4dc13bb83a16d4ff9865a51b3e4d24112327c526c1392e14d56f20d6f4eaf382"
      reference = "https://twitter.com/juanandres_gs/status/1496930731351805953"
    strings:
        $string1 = "/403forBiden/" wide ascii nocase
        $string2 = "/wHiteHousE/" wide ascii 
        $string3 = "vote_result." wide ascii
        $string4 = "partyTicket." wide ascii
        $buildid1 = "Go build ID: \"qb0H7AdWAYDzfMA1J80B/nJ9FF8fupJl4qnE4WvA5/PWkwEJfKUrRbYN59_Jba/2o0VIyvqINFbLsDsFyL2\"" wide ascii
        $project1 = "C:/projects/403forBiden/wHiteHousE/" wide ascii
    condition:
      uint16(0) == 0x5A4D and
      (2 of ($string*) or 
        any of ($buildid*) or 
        any of ($project*))
}
