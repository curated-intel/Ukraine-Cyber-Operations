rule PartyTicket : malware {
    meta:
        description = "PartyTicket ransomware during ukraine conflict, written in GO"
        source = "Orange CD"
        date = "28/02/22"
        researcher = "Alexandre MATOUSEK"
        category = "ransom"
    strings:
        $ = "read_me.html"
        $ = "403forBiden" nocase
        $ = "wHiteHousE.go" nocase
        $ = ".encryptedJB"
    condition:
        all of them
}
