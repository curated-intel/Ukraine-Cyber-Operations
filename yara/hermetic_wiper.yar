rule hermetic_wiper { 
    meta:  
        description = "Yara rule for the detection of DiskKill/HermeticWiper sample"  
        author = "Yoroi Malware ZLab" 
        last_updated = "2022-02-24"  
        tlp = "WHITE" 
        category = “informational” 
    
    strings: 
        $a = {458c660fd6459cffd350ffd78bf885ff0f84f70000006a008d8578ffffff506a60576a006a006864000900ff75a4ff1564504000576a0085c07510ffd38b3d70} 

    condition: 
        $a and uint16(0) == 0x5A4D 
}
