![logo](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/ci-logo.png)

# Ukraine-Cyber-Operations
Curated Intelligence is working with analysts from around the world to provide useful information to organisations in Ukraine looking for additional free threat intelligence. Slava Ukraini. Glory to Ukraine. ([Blog](https://www.curatedintel.org/2021/08/welcome.html) | [Twitter](https://twitter.com/CuratedIntel) | [LinkedIn](https://www.linkedin.com/company/curatedintelligence/))

![timeline](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/UkraineTimelineUpdated.png)

![cyberwar](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/Russia-Ukraine%20Cyberwar.png)

### Analyst Comments:

- 2022-02-25
  - Creation of the initial repository to help organisations in Ukraine
  - Added [Threat Reports](https://github.com/curated-intel/Ukraine-Cyber-Operations#threat-reports) section
  - Added [Vendor Support](https://github.com/curated-intel/Ukraine-Cyber-Operations#vendor-support) section
- 2022-02-26
  - Additional resources, chronologically ordered (h/t Orange-CD)
  - Added [Vetted OSINT Sources](https://github.com/curated-intel/Ukraine-Cyber-Operations#vetted-osint-sources) section 
  - Added [Miscellaneous Resources](https://github.com/curated-intel/Ukraine-Cyber-Operations#miscellaneous-resources) section
- 2022-02-27
  - Additional threat reports have been added
  - Added [Data Brokers](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/README.md#data-brokers) section
  - Added [Access Brokers](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/README.md#access-brokers) section
- 2022-02-28
  - Added Russian Cyber Operations Against Ukraine Timeline by ETAC
  - Added Vetted and Contextualized [Indicators of Compromise (IOCs)](https://github.com/curated-intel/Ukraine-Cyber-Operations/tree/main/ETAC_IOCs) by ETAC
- 2022-03-01
  - Additional threat reports and resources have been added
- 2022-03-02
  - Additional IOCs have been added
  - Added vetted [YARA rule collection](https://github.com/curated-intel/Ukraine-Cyber-Operations/tree/main/yara) from the Threat Reports by ETAC
  - Added loosely-vetted [IOC Threat Hunt Feeds](https://github.com/curated-intel/Ukraine-Cyber-Operations/tree/main/KPMG-Egyde_Ukraine-Crisis_Feeds/MISP-CSV_MediumConfidence_Filtered) by KPMG-Egyde CTI (h/t [0xDISREL](https://twitter.com/0xDISREL))
    - IOCs shared by these feeds are `LOW-TO-MEDIUM CONFIDENCE` we strongly recommend NOT adding them to a blocklist
    - These could potentially be used for `THREAT HUNTING` and could be added to a `WATCHLIST`
    - IOCs are generated in `MISP COMPATIBLE` CSV format
- 2022-03-03
  - Additional threat reports and vendor support resources have been added
  - Updated [Log4Shell IOC Threat Hunt Feeds](https://github.com/curated-intel/Log4Shell-IOCs/tree/main/KPMG_Log4Shell_Feeds) by KPMG-Egyde CTI; not directly related to Ukraine, but still a widespread vulnerability.
  - Added diagram of Russia-Ukraine Cyberwar Participants 2022 by ETAC
  - Additional IOCs have been added
- 2022-03-04
  - Additional [Threat Hunt Feed](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/KPMG-Egyde_Ukraine-Crisis_Feeds/MISP-CSV_LowConfidence_Unfiltered/Ukraine-Crisis_DomainTools_ThreatHunt_Feed.csv) for recently registered Ukrainian domain names (h/t DomainTools)
  - Additional [Threat Hunt Feed](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/KPMG-Egyde_Ukraine-Crisis_Feeds/MISP-CSV_MediumConfidence_Filtered/Ukraine-Crisis_RecordedFuture_ThreatHunt_Feed.csv) for threat groups targeting Ukraine (h/t RecordedFuture)
- 2022-03-05
  - Additional threat reports have been added
- 2022-03-06
  - Additional [Miscellaneous Resources](https://github.com/curated-intel/Ukraine-Cyber-Operations#miscellaneous-resources) for understanding the Ukraine-conflict (h/t UT CREEES)
- 2022-03-07
  - Additional Threat Reports have been added
  - Additional IOCs have been added
- 2022-03-08
  - Additional Threat Reports have been added
  - Additional IOCs have been added
- 2022-03-09
  - Additional Threat Reports have been added
  - Additional YARA rules have been added
- 2022-03-14
  - An updated Timeline of attacks has been added 
  - Additional Threat Reports have been added
  - Additional IOCs have been added
  - Additional YARA rules have been added
- 2022-03-15
  - Additional Threat Reports have been added
  - Additional IOCs have been added
- 2022-03-18
  - Additional Threat Reports have been added
  - Additional IOCs have been added to the master CSV file
  - A new CSV for CERT-UA IOCs specifically has been created - see [here](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/ETAC_IOCs/CERT-UA_IOCs.csv)
- 2022-03-19
  - Additional Threat Reports have been added
  - Additional IOCs have been added
- 2022-03-20
  - Additional YARA rules have been added (h/t [Arkbird_SOLG](https://twitter.com/Arkbird_SOLG))
- 2022-03-21
  - An Additional Threat Report has been added
  - Additional YARA rules have been added
- 2022-03-23
  - Additional Threat Reports have been added
  - Additional IOCs have been added
- 2022-03-25
  - Additional Threat Reports have been added
  - Additional IOCs have been added
- 2022-03-28
  - Additional Threat Reports have been added
  - Additional IOCs have been added

#### `Threat Reports`
| Date | Source | Threat(s) | URL |
| --- | --- | --- | --- |
| 14 JAN | SSU Ukraine | Website Defacements | [ssu.gov.ua](https://ssu.gov.ua/novyny/sbu-rozsliduie-prychetnist-rosiiskykh-spetssluzhb-do-sohodnishnoi-kiberataky-na-orhany-derzhavnoi-vlady-ukrainy)|
| 15 JAN | Microsoft | WhisperGate wiper (DEV-0586) | [microsoft.com](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/) |
| 19 JAN | Elastic | WhisperGate wiper (Operation BleedingBear) | [elastic.github.io](https://elastic.github.io/security-research/malware/2022/01/01.operation-bleeding-bear/article/) |
| 31 JAN | Symantec | Gamaredon/Shuckworm/PrimitiveBear (FSB) | [symantec-enterprise-blogs.security.com](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-gamaredon-espionage-ukraine) |
| 2 FEB | RaidForums | Access broker "GodLevel" offering Ukrainain algricultural exchange | RaidForums [not linked] |
| 2 FEB | CERT-UA | UAC-0056 using SaintBot and OutSteel malware | [cert.gov.ua](https://cert.gov.ua/article/18419) |
| 3 FEB | PAN Unit42 | Gamaredon/Shuckworm/PrimitiveBear (FSB) | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/gamaredon-primitive-bear-ukraine-update-2021/) |
| 4 FEB | Microsoft | Gamaredon/Shuckworm/PrimitiveBear (FSB) | [microsoft.com](https://www.microsoft.com/security/blog/2022/02/04/actinium-targets-ukrainian-organizations/) |
| 8 FEB | NSFOCUS | Lorec53 (aka UAC-0056, EmberBear, BleedingBear) | [nsfocusglobal.com](https://nsfocusglobal.com/apt-retrospection-lorec53-an-active-russian-hack-group-launched-phishing-attacks-against-georgian-government) |
| 15 FEB | CERT-UA | DDoS attacks against the name server of government websites as well as Oschadbank (State Savings Bank) & Privatbank (largest commercial bank). False SMS and e-mails to create panic | [cert.gov.ua](https://cert.gov.ua/article/37139) |
| 23 FEB | The Daily Beast | Ukrainian troops receive threatening SMS messages | [thedailybeast.com](https://www.thedailybeast.com/cyberattacks-hit-websites-and-psy-ops-sms-messages-targeting-ukrainians-ramp-up-as-russia-moves-into-ukraine) |
| 23 FEB | UK NCSC | Sandworm/VoodooBear (GRU) | [ncsc.gov.uk](https://www.ncsc.gov.uk/files/Joint-Sandworm-Advisory.pdf) |
| 23 FEB | SentinelLabs | HermeticWiper | [sentinelone.com]( https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/ ) |
| 24 FEB | ESET | HermeticWiper | [welivesecurity.com](https://www.welivesecurity.com/2022/02/24/hermeticwiper-new-data-wiping-malware-hits-ukraine/) |
| 24 FEB | Symantec | HermeticWiper, PartyTicket ransomware, CVE-2021-1636, unknown webshell | [symantec-enterprise-blogs.security.com](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ukraine-wiper-malware-russia) |
| 24 FEB | Cisco Talos | HermeticWiper | [blog.talosintelligence.com](https://blog.talosintelligence.com/2022/02/threat-advisory-hermeticwiper.html) |
| 24 FEB | Zscaler | HermeticWiper | [zscaler.com](https://www.zscaler.com/blogs/security-research/hermetic-wiper-resurgence-targeted-attacks-ukraine) |
| 24 FEB | Cluster25 | HermeticWiper | [cluster25.io](https://cluster25.io/2022/02/24/ukraine-analysis-of-the-new-disk-wiping-malware/) |
| 24 FEB | CronUp | Data broker "FreeCivilian" offering multiple .gov.ua | [twitter.com/1ZRR4H](https://twitter.com/1ZRR4H/status/1496931721052311557)|
| 24 FEB | RaidForums | Data broker "Featherine" offering diia.gov.ua | RaidForums [not linked] |
| 24 FEB | DomainTools | Unknown scammers | [twitter.com/SecuritySnacks](https://twitter.com/SecuritySnacks/status/1496956492636905473?s=20&t=KCIX_1Ughc2Fs6Du-Av0Xw) |
| 25 FEB | @500mk500 | Gamaredon/Shuckworm/PrimitiveBear (FSB) | [twitter.com/500mk500](https://twitter.com/500mk500/status/1497339266329894920?s=20&t=opOtwpn82ztiFtwUbLkm9Q) |
| 25 FEB | @500mk500 | Gamaredon/Shuckworm/PrimitiveBear (FSB) | [twitter.com/500mk500](https://twitter.com/500mk500/status/1497208285472215042)|
| 25 FEB | Microsoft | HermeticWiper | [gist.github.com](https://gist.github.com/fr0gger/7882fde2b1b271f9e886a4a9b6fb6b7f) |
| 25 FEB | 360 NetLab | DDoS (Mirai, Gafgyt, IRCbot, Ripprbot, Moobot) | [blog.netlab.360.com](https://blog.netlab.360.com/some_details_of_the_ddos_attacks_targeting_ukraine_and_russia_in_recent_days/) |
| 25 FEB | Conti [themselves] | Conti ransomware, BazarLoader | Conti News .onion [not linked] |
| 25 FEB | CoomingProject [themselves] | Data Hostage Group | CoomingProject Telegram [not linked] |
| 25 FEB | CERT-UA | UNC1151/Ghostwriter (Belarus MoD) | [CERT-UA Facebook](https://facebook.com/story.php?story_fbid=312939130865352&id=100064478028712)|
| 25 FEB | Sekoia | UNC1151/Ghostwriter (Belarus MoD) | [twitter.com/sekoia_io](https://twitter.com/sekoia_io/status/1497239319295279106) |
| 25 FEB | @jaimeblascob | UNC1151/Ghostwriter (Belarus MoD) | [twitter.com/jaimeblasco](https://twitter.com/jaimeblascob/status/1497242668627370009)|
| 25 FEB | RISKIQ | UNC1151/Ghostwriter (Belarus MoD) | [community.riskiq.com](https://community.riskiq.com/article/e3a7ceea/) |
| 25 FEB | MalwareHunterTeam | Unknown phishing | [twitter.com/malwrhunterteam](https://twitter.com/malwrhunterteam/status/1497235270416097287) |
| 25 FEB | ESET | Unknown scammers | [twitter.com/ESETresearch](https://twitter.com/ESETresearch/status/1497194165561659394) |
| 25 FEB | BitDefender | Unknown scammers | [blog.bitdefender.com](https://blog.bitdefender.com/blog/hotforsecurity/cybercriminals-deploy-spam-campaign-as-tens-of-thousands-of-ukrainians-seek-refuge-in-neighboring-countries/) |
| 25 FEB | SSSCIP Ukraine | Unkown phishing | [twitter.com/dsszzi](https://twitter.com/dsszzi/status/1497103078029291522) |
| 25 FEB | RaidForums | Data broker "NetSec"  offering FSB (likely SMTP accounts) | RaidForums [not linked] |
| 25 FEB | Zscaler | PartyTicket decoy ransomware | [zscaler.com](https://www.zscaler.com/blogs/security-research/technical-analysis-partyticket-ransomware) |
| 25 FEB | INCERT GIE | Cyclops Blink, HermeticWiper | [linkedin.com](https://www.linkedin.com/posts/activity-6902989337210740736-XohK) [Login Required] |
| 25 FEB | Proofpoint | UNC1151/Ghostwriter (Belarus MoD) | [twitter.com/threatinsight](https://twitter.com/threatinsight/status/1497355737844133895?s=20&t=Ubi0tb_XxGCbHLnUoQVp8w) |
| 25 FEB | @fr0gger_ | HermeticWiper capabilities Overview | [twitter.com/fr0gger_](https://twitter.com/fr0gger_/status/1497121876870832128?s=20&t=_296n0bPeUgdXleX02M9mg)
| 25 FEB | Netskope | HermeticWiper analysis | [netskope.com](https://www.netskope.com/pt/blog/netskope-threat-coverage-hermeticwiper) |
| 26 FEB | BBC Journalist | A fake Telegram account claiming to be President Zelensky is posting dubious messages | [twitter.com/shayan86](https://twitter.com/shayan86/status/1497485340738785283?s=21) |
| 26 FEB | CERT-UA | UNC1151/Ghostwriter (Belarus MoD) | [CERT_UA Facebook](https://facebook.com/story.php?story_fbid=313517477474184&id=100064478028712) |
| 26 FEB | MHT and TRMLabs | Unknown scammers, linked to ransomware | [twitter.com/joes_mcgill](https://twitter.com/joes_mcgill/status/1497609555856932864?s=20&t=KCIX_1Ughc2Fs6Du-Av0Xw) |
| 26 FEB | US CISA | WhisperGate wiper, HermeticWiper | [cisa.gov](https://www.cisa.gov/uscert/ncas/alerts/aa22-057a) |
| 26 FEB | Bloomberg | Destructive malware (possibly HermeticWiper) deployed at Ukrainian Ministry of Internal Affairs & data stolen from Ukrainian telecommunications networks | [bloomberg.com](https://www.bloomberg.com/news/articles/2022-02-26/hackers-destroyed-data-at-key-ukraine-agency-before-invasion?sref=ylv224K8) |
| 26 FEB | Vice Prime Minister of Ukraine | IT ARMY of Ukraine created to crowdsource offensive operations against Russian infrastructure | [twitter.com/FedorovMykhailo](https://twitter.com/FedorovMykhailo/status/1497642156076511233) |
| 26 FEB | Yoroi | HermeticWiper | [yoroi.company](https://yoroi.company/research/diskkill-hermeticwiper-a-disruptive-cyber-weapon-targeting-ukraines-critical-infrastructures) |
| 27 FEB | LockBit [themselves] | LockBit ransomware | LockBit .onion [not linked] | 
| 27 FEB | ALPHV [themselves] | ALPHV ransomware | vHUMINT [closed source] |
| 27 FEB | Mēris Botnet [themselves] | DDoS attacks | vHUMINT [closed source] |
| 28 FEB | Horizon News [themselves] | Leak of China's Censorship Order about Ukraine | [techarp.com](https://www-techarp-com.cdn.ampproject.org/c/s/www.techarp.com/internet/chinese-media-leaks-ukraine-censor/?amp=1)|
| 28 FEB | Microsoft | FoxBlade (aka HermeticWiper) | [blogs.microsoft.com](https://blogs.microsoft.com/on-the-issues/2022/02/28/ukraine-russia-digital-war-cyberattacks/?preview_id=65075) |
| 28 FEB | @heymingwei | Potential BGP hijacks attempts against Ukrainian Internet Names Center | [twitter.com/heymingwei](https://twitter.com/heymingwei/status/1498362715198263300?s=20&t=Ju31gTurYc8Aq_yZMbvbxg) |
| 28 FEB | @cyberknow20 | Stormous ransomware targets Ukraine Ministry of Foreign Affairs | [twitter.com/cyberknow20](https://twitter.com/cyberknow20/status/1498434090206314498?s=21) | 
| 1 MAR | ESET | IsaacWiper and HermeticWizard | [welivesecurity.com](https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/) |
| 1 MAR | Proofpoint | Ukrainian armed service member's email compromised and sent malspam containing the SunSeed malware (likely TA445/UNC1151/Ghostwriter) | [proofpoint.com](https://www.proofpoint.com/us/blog/threat-insight/asylum-ambuscade-state-actor-uses-compromised-private-ukrainian-military-emails) |
| 1 MAR | Elastic | HermeticWiper | [elastic.github.io](https://elastic.github.io/security-research/intelligence/2022/03/01.hermeticwiper-targets-ukraine/article/) |
| 1 MAR | CrowdStrike | PartyTicket (aka HermeticRansom), DriveSlayer (aka HermeticWiper) | [CrowdStrike](https://www.crowdstrike.com/blog/how-to-decrypt-the-partyticket-ransomware-targeting-ukraine/) |
| 2 MAR | Zscaler | DanaBot operators launch DDoS attacks against the Ukrainian Ministry of Defense | [zscaler.com](https://www.zscaler.com/blogs/security-research/danabot-launches-ddos-attack-against-ukrainian-ministry-defense) |
| 2 MAR | Infoblox | Ukrainian Support Fraud | [blogs.infoblox.com](https://blogs.infoblox.com/cyber-threat-intelligence/cyber-threat-advisory/cyber-threat-advisory-ukrainian-support-fraud/) |
| 2 MAR | Trellix | Digging into HermeticWiper | [trellix.com](https://www.trellix.com/en-us/about/newsroom/stories/threat-labs/digging-into-hermeticwiper.html) |
| 2 MAR | Port Swigger | Ukraine invasion: WordPress-hosted university websites hacked in ‘targeted attacks’ | [portswigger.net](https://portswigger.net/daily-swig/ukraine-invasion-wordpress-hosted-university-websites-hacked-in-targeted-attacks) |
| 3 MAR | @ShadowChasing1 | Gamaredon/Shuckworm/PrimitiveBear (FSB) | [twitter.com/ShadowChasing1](https://twitter.com/ShadowChasing1/status/1499361093059153921) |
| 3 MAR | @vxunderground | News website in Poland was reportedly compromised and the threat actor uploaded anti-Ukrainian propaganda | [twitter.com/vxunderground](https://twitter.com/vxunderground/status/1499374914758918151?s=20&t=jyy9Hnpzy-5P1gcx19bvIA) |
| 3 MAR | @kylaintheburgh | Russian botnet on Twitter is pushing "#istandwithputin" and "#istandwithrussia" propaganda (in English) | [twitter.com/kylaintheburgh](https://twitter.com/kylaintheburgh/status/1499350578371067906?s=21) |
| 3 MAR | @tracerspiff | UNC1151/Ghostwriter (Belarus MoD) | [twitter.com](https://twitter.com/tracerspiff/status/1499444876810854408?s=21) |
| 3 MAR | Trustwave | Gorenie Fundraising Email Scams | [trustwave.com](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/dark-web-insights-evolving-cyber-tactics-aim-to-impact-the-russia-ukraine-conflict/) 
| 3 MAR | Trend Micro | Prominent Cyber Attacks in Russia-Ukraine Conflict | [trendmicro.com](https://www.trendmicro.com/en_us/research/22/c/cyberattacks-are-prominent-in-the-russia-ukraine-conflict.html) |
| 3 MAR | U.S. DoT | Press Releases: Treasury Sanctions Russians Bankrolling Putin and Russia-Backed Influence Actors | [treasury.gov](https://home.treasury.gov/news/press-releases/jy0628) |
| 3 MAR | Microsoft MSTIC | DEV-0586 (aka WhisperGate), DEV-0665 (aka FoxBlade/HermeticWizard/HermeticWiper), SonicVote (aka HermeticRansom & PartyTicket), Lasainraw (aka IsaacWiper) | [twitter.com/MalwareRE](https://twitter.com/MalwareRE/status/1499209531670335498) |
| 4 MAR | Interfax | CERT-UA warns about mass mailings of malicious software | [interfax.com.ua](https://en.interfax.com.ua/news/general/807175.html) |
| 4 MAR | eln0ty | HermeticWiper/FoxBlade Analysis (in-depth) | [eln0ty.github.io](https://eln0ty.github.io/malware%20analysis/HermeticWiper/) |
| 4 MAR | Mandiant | Sandworm, UNC2589 (aka Lorec53/UAC-0056/EmberBear), UNC3715 (aka DEV-0665/HermeticWiper), and potentially TEMP.Isotope (aka BerserkBear/EnergeticBear/Dragonfly) | [mandiant.com](https://www.mandiant.com/resources/russia-invasion-ukraine-retaliation) |
| 5 MAR | SSSCIP Ukraine |  Russian DDos attacks (100 Gbps at their peak)  primarily aimed at the resources of Verkhovna Rada, Cabinet of Ministers, President of Ukraine, Defense Ministry and Internal Affairs Ministry | [twitter.com/dsszzi](https://twitter.com/dsszzi/status/1500090448735621128) |
| 6 MAR | @shakirov2036 | Notice Russian Government Websites To move to domestic hosting thread | [twitter.com/shakirov2036](https://twitter.com/shakirov2036/status/1500584933491982341) |
| 7 MAR | ReverseMode | SATCOM terminals under attack in Europe: plausible analysis | [reversemode.com](https://www.reversemode.com/2022/03/satcom-terminals-under-attack-in-europe.html) |
| 7 MAR | Google TAG | FancyBear (aka APT28) targeted users of UkrNet (a Ukrainian media company), Ghostwriter (aka UNC1151), Mustang Panda (aka Temp.Hex), DDoS attacks | [blog.google](https://blog.google/threat-analysis-group/update-threat-landscape-ukraine/) |
| 7 MAR | CERT-UA | UAC-0051 (aka UNC1151), MicroBackdoor, CVE-2019-0541 | [cert.gov.ua](https://cert.gov.ua/article/37626) |
| 8 MAR | Cluster25 | UNC1151/Ghostwriter (Belarus MoD) | [cluster25.io](https://cluster25.io/2022/03/08/ghostwriter-unc1151-adopts-microbackdoor-variants-in-cyber-operations-against-targets-in-ukraine/) |
| 8 MAR | Trend Micro | RURansom - a data wiper targeting Russian organizations | [trendmicro.com](https://www.trendmicro.com/en_us/research/22/c/new-ruransom-wiper-targets-russia.html) |
| 9 MAR | ReversingLabs | HermeticWiper and IsaacWiper | [blog.reversinglabs.com](https://blog.reversinglabs.com/blog/wiper-malware-targeting-ukraine-evidence-of-planning-and-haste) |
| 11 MAR | CERT-UA | UAC-0056 (aka Lorec53, EmberBear) push fake antivirus updates containing Cobalt Strike Beacons, GrimImplant, and GraphSteel malspam against state authorities of Ukraine | [cert.gov.ua](https://cert.gov.ua/article/37704) |
| 11 MAR | Infosec Magazine | pro-Ukrainian actors should be wary of downloading DDoS tools to attack Russia, as they may be booby-trapped with info-stealing malware | [infosecurity-magazine.com](https://www.infosecurity-magazine.com/news/ukrainian-it-army-hijacked-malware/) |
| 11 MAR | @cyberknow20 | "Xahnet" shared a video they allegedly left a message and defaced the main page of Ukraine's capital bank [unvalidated] | [twitter.com/cyberknow20](https://twitter.com/cyberknow20/status/1502166591466659840?s=21) |
| 13 MAR | Spiegel | German Anonymous hacktivists target Rosneft Germany, allegedly stole 20TB of data, deleted 59 Apple devices remotely, and left "Slava Ukraini" on wiped systems | [spiegel.de](https://www.spiegel.de/netzwelt/web/bundeskriminalamt-ermittelt-hackerangriff-auf-rosneft-deutschland-a-74e3a53a-e747-4500-8198-ea6780a7d79a) |
| 13 MAR | BeeHive | Twitter user "BeeHive" allegedly exploited a vulnerability in the open-source ADS-B radar reporting feeds and digital transponders to manipulate Russian airlines, causing Aeroflot planes to erroneously squawk "7700" (for emergencies) and display anti-Russian callsigns on flight radars | [twitter.com/BeeHiveCyberSec](https://twitter.com/BeeHiveCyberSec/status/1503079608639320072?s=20&t=LDtQhFLUO3qAckLA1ryKmQ) |
| 14 MAR | Cisco Talos | Opportunistic cybercriminals take advantage of Ukraine invasion | [blog.talosintelligence.com](https://blog.talosintelligence.com/2022/03/ukraine-invasion-scams-malware.html?m=1) |
| 14 MAR | ESET | Another wiper was discovered targeting Ukraine, dubbed CaddyWiper, which was delivered via GPO, indicating the adversary had prior control of the target's network beforehand. CaddyWiper is seeminginly not connected to other the wipers targeting Ukraine, including Whispergate, HermeticWiper, or IsaacWiper | [twitter.com/ESETresearch](https://twitter.com/ESETresearch/status/1503436420886712321) |
| 15 MAR | VICE | The Security Service of Ukraine (SBU) detained a “hacker” who provided assistance to Russian troops in Ukraine by routing phone calls on their behalf, and sent text messages to Ukrainian security forces suggesting they surrender | [vice.com](https://www.vice.com/en/article/v7djda/ukraine-arrests-hacker-routing-calls-for-russian-troops) |
| 15 MAR | SentinelOne | Threat Actor UAC-0056 Targeting Ukraine with Fake Translation Software | [sentinelone.com/blog](https://www.sentinelone.com/blog/threat-actor-uac-0056-targeting-ukraine-with-fake-translation-software/) |
| 16 MAR | CERT-UA | QR code phishing posing as UKR.NET linked to UAC-0028 group (APT28/FancyBear/GRU) | [cert.gov.ua](https://cert.gov.ua/article/37788) |
| 17 MAR | CERT-UA | UAC-0020 (Vermin) cyberattack on Ukrainian state organizations using the SPECTR malware, whose activities are associated with the so-called security agencies of the so-called "Luhansk People's Republic" | [cert.gov.ua](https://cert.gov.ua/article/37815) |
| 18 MAR | CERT-UA | UAC-0035 (InvisiMole) cyberattack on State Organizations of Ukraine | [cert.gov.ua](https://cert.gov.ua/article/37829) |
| 22 MAR | CERT-UA | UAC-0088 deploys DoubleZero wiper | [cert.gov.ua](https://cert.gov.ua/article/38088) |
| 22 MAR | CERT-UA | UAC-0026 cyberattack using HeaderTip malware, linked to [Scarab APT](https://twitter.com/aRtAGGI/status/1506010831221248002) | [cert.gov.ua](https://cert.gov.ua/article/38097) |
| 23 MAR | Interfax UA | Datagroup, a provider of fiber-optic infrastructure and digital services, resolved more than 350 DDoS attacks on the country's telecommunications network during the month of the war. The largest attack was 103.6 Gbps, 28.0 Mpps; the most powerful attack was 27.6 Gbps, 43.0 Mpps; the longest attack was 24 days. | [interfax.com.ua](https://en.interfax.com.ua/news/telecom/817143.html) |
| 23 MAR | BalkanInsight | Croatian police are probing the hacking of the ‘Slobodna Dalmacija’ website, where hackers replaced content with pro-Russian articles on Ukraine. “Western Deception Machine”, “Which Side Are You On?”, and “The United States of America Admitted They Have Hidden Laboratories in Ukraine”, are just some of the fake articles that the hackers posted online. | [balkaninsight.com](https://balkaninsight.com/2022/03/23/hackers-attack-croatian-daily-post-kremlin-propaganda/) |
| 23 MAR | CERT-UA | UAC-0051 group (UNC1151/GhostWriter), Cobalt Strike Beacons | [cert.gov.ua](https://cert.gov.ua/article/38155) |
| 24 MAR | SentinelOne | Ukraine CERT (CERT-UA) has released new details on UAC-0026, which SentinelLabs confirms is associated with the suspected Chinese threat actor known as Scarab. Scarab has conducted a number of campaigns over the years, making use of a custom backdoor originally known as Scieron, which may be the predecessor to HeaderTip. | [sentinelone.com](https://www.sentinelone.com/labs/chinese-threat-actor-scarab-targeting-ukraine/) |
| 24 MAR | Lab52 | Quasar RAT spear-phishing campaign | [lab52.io](https://lab52.io/blog/another-cyber-espionage-campaign-in-the-russia-ukrainian-ongoing-cyber-attacks/) |
| 25 MAR | SSSCIP Ukraine | Who is behind the Cyberattacks on Ukraine's Critical Information Infrastructure: Statistics for March 15-22 | [cip.gov.ua](https://cip.gov.ua/en/news/khto-stoyit-za-kiberatakami-na-ukrayinsku-kritichnu-informaciinu-infrastrukturu-statistika-15-22-bereznya) |
| 25 MAR | SSSCIP Ukraine | Statistics of Cyber Attacks on Ukrainian Critical Information Infrastructure: 15-22 March | [cip.gov.ua](https://cip.gov.ua/en/news/statistika-kiberatak-na-ukrayinsku-kritichnu-informaciinu-infrastrukturu-15-22-bereznya) |
| 26 MAR | @_n0p_ | Analysis of a Caddy Wiper Sample | [n0p.me](https://n0p.me/2022/03/2022-03-26-caddywiper/) |
| 28 MAR | CERT-UA | Cyberattack on Ukrainian state authorities using pseudoSteel malware linked to UAC-0010 (Armageddon/Gamaredon) | [cert.gov.ua](https://cert.gov.ua/article/38371) |
| 28 MAR | Cyber, etc | Ukraine's largest fix-line telecommunications operator hit by cyber attack | [Cyber, etc](https://twitter.com/cyber_etc/status/1508498145831010315) |
| 28 MAR | SSSCIP Ukraine | Cyberattack against Ukrtelecom IT-infrastructure and recovery | [twitter.com/ dsszzi](https://twitter.com/dsszzi/status/1508528209075257347) |
| 28 MAR | CERT-UA | GraphSteel and GrimPlant, UAC-0056 | [cert.gov.ua](https://cert.gov.ua/article/38374) |
| 29 MAR | Newsweek | U.S. Airport hit with Cyberattack over Ukraine | [Newsweek](https://www.newsweek.com/us-airport-hit-cyberattack-over-ukraine-no-one-afraid-you-1692903) |
| 29 MAR | ZDnet | The Security Service of Ukraine (SBU) has destroyed five "enemy" bot farms engaged in activities to frighten Ukrainian citizens. In a March 28 release, the SBU said that the bot farms had an overall capacity of at least 100,000 accounts spreading misinformation and fake news surrounding Russia's invasion of Ukraine | [zdnet.com](https://www.zdnet.com/article/ukraine-takes-out-five-bot-farms-spreading-panic-among-citizens/) |
| 30 MAR | Viasat | Viasat is providing an overview and incident report on the cyber-attack against the KA-SAT network, which occurred on 24 February 2022, and resulted in a partial interruption of KA-SAT's consumer-oriented satellite broadband service. | [viasat.com](https://www.viasat.com/about/newsroom/blog/ka-sat-network-cyber-attack-overview/) |
| 30 MAR | CrowdStrike | EMBER BEAR (aka UAC-0056, Lorec53, Lorec Bear, Bleeding Bear, Saint Bear) | [crowdstrike.com](https://www.crowdstrike.com/blog/who-is-ember-bear/) |
| 30 MAR | CERT-UA | MarsStealer, UAC-0041 | [cert.gov.ua](https://cert.gov.ua/article/38606) |
| 30 MAR | Google TAG | Curious Gorge (APT from China), COLDRIVER (APT from Russia), Ghostwriter (APT from Belarus) | [blog.google](https://blog.google/threat-analysis-group/tracking-cyber-activity-eastern-europe/) |

#### `Access Brokers`
| Date | Threat(s) | Source |
| --- | --- | --- |
| 23 JAN | Access broker "Mont4na" offering UkrFerry | RaidForums [not linked] |
| 23 JAN | Access broker "Mont4na" offering PrivatBank | RaidForums [not linked] |
| 24 JAN | Access broker "Mont4na" offering DTEK | RaidForums [not linked] |
| 27 FEB | KelvinSecurity Sharing list of IP cameras in Ukraine | vHUMINT [closed source] |
| 28 FEB | "w1nte4mute" looking to buy access to UA and NATO countries (likely ransomware affiliate) | vHUMINT [closed source] |

#### `Data Brokers`
| Threat Actor    | Type            | Observation                                                                                               | Validated | Relevance                     | Source                                                     |
| --------------- | --------------- | --------------------------------------------------------------------------------------------------------- | --------- | ----------------------------- | ---------------------------------------------------------- |
| aguyinachair    | UA data sharing | PII DB of ukraine.com (shared as part of a generic compilation)                                           | No        | TA discussion in past 90 days | ELeaks Forum \[not linked\]                                |
| an3key          | UA data sharing | DB of Ministry of Communities and Territories Development of Ukraine (minregion\[.\]gov\[.\]ua)           | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| an3key          | UA data sharing | DB of Ukrainian Ministry of Internal Affairs (wanted\[.\]mvs\[.\]gov\[.\]ua)                              | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | PII DB (40M) of PrivatBank customers (privatbank\[.\]ua)                                                  | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | DB of "border crossing" DBs of DPR and LPR                                                                | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | PII DB (7.5M) of Ukrainian passports                                                                      | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | PII DB of Ukrainian car registration, license plates, Ukrainian traffic police records                    | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | PII DB (2.1M) of Ukrainian citizens                                                                       | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | PII DB (28M) of Ukrainian citizens (passports, drivers licenses, photos)                                  | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | PII DB (1M) of Ukrainian postal/courier service customers (novaposhta\[.\]ua)                             | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | PII DB (10M) of Ukrainian telecom customers (vodafone\[.\]ua)                                             | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | PII DB (3M) of Ukrainian telecom customers (lifecell\[.\]ua)                                              | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| CorelDraw       | UA data sharing | PII DB (13M) of Ukrainian telecom customers (kyivstar\[.\]ua)                                             | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| danieltx51      | UA data sharing | DB of Ministry of Foreign Affairs of Ukraine (mfa\[.\]gov\[.\]ua)                                         | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| DueDiligenceCIS | UA data sharing | PII DB (63M) of Ukrainian citizens (name, DOB, birth country, phone, TIN, passport, family, etc)          | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| Featherine      | UA data sharing | DB of Ukrainian 'Diia' e-Governance Portal for Ministry of Digital Transformation of Ukraine              | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| FreeCivilian    | UA data sharing | DB of Ministry for Internal Affairs of Ukraine public data search engine (wanted\[.\]mvs\[.\]gov\[.\]ua)  | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| FreeCivilian    | UA data sharing | DB of Ministry for Communities and Territories Development of Ukraine (minregion\[.\]gov\[.\]ua)          | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| FreeCivilian    | UA data sharing | DB of Motor Insurance Bureau of Ukraine (mtsbu\[.\]ua)                                                    | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| FreeCivilian    | UA data sharing | PII DB of Ukrainian digital-medicine provider (medstar\[.\]ua)                                            | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| FreeCivilian    | UA data sharing | DB of ticket.kyivcity.gov.ua                                                                              | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of id.kyivcity.gov.ua                                                                                  | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of my.kyivcity.gov.ua                                                                                  | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of portal.kyivcity.gov.ua                                                                              | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of anti-violence-map.msp.gov.ua                                                                        | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of dopomoga.msp.gov.ua                                                                                 | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of e-services.msp.gov.ua                                                                               | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of edu.msp.gov.ua                                                                                      | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of education.msp.gov.ua                                                                                | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of ek-cbi.msp.gov.ua                                                                                   | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mail.msp.gov.ua                                                                                     | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of portal-gromady.msp.gov.ua                                                                           | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of web-minsoc.msp.gov.ua                                                                               | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of wcs-wim.dsbt.gov.ua                                                                                 | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of bdr.mvs.gov.ua                                                                                      | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of motorsich.com                                                                                       | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of dsns.gov.ua                                                                                         | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mon.gov.ua                                                                                          | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of minagro.gov.ua                                                                                      | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of zt.gov.ua                                                                                           | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of kmu.gov.ua                                                                                          | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mvs.gov.ua                                                                                          | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of dsbt.gov.ua                                                                                         | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of forest.gov.ua                                                                                       | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of nkrzi.gov.ua                                                                                        | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of dabi.gov.ua                                                                                         | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of comin.gov.ua                                                                                        | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of dp.dpss.gov.ua                                                                                      | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of esbu.gov.ua                                                                                         | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mms.gov.ua                                                                                          | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mova.gov.ua                                                                                         | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mspu.gov.ua                                                                                         | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of nads.gov.ua                                                                                         | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of reintegration.gov.ua                                                                                | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of sies.gov.ua                                                                                         | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of sport.gov.ua                                                                                        | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mepr.gov.ua                                                                                         | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mfa.gov.ua                                                                                          | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of va.gov.ua                                                                                           | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mtu.gov.ua                                                                                          | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of cg.mvs.gov.ua                                                                                       | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of ch-tmo.mvs.gov.ua                                                                                   | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of cp.mvs.gov.ua                                                                                       | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of cpd.mvs.gov.ua                                                                                      | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of hutirvilnij-mrc.mvs.gov.ua                                                                          | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of dndekc.mvs.gov.ua                                                                                   | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of visnyk.dndekc.mvs.gov.ua                                                                            | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of dpvs.hsc.gov.ua                                                                                     | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of odk.mvs.gov.ua                                                                                      | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of e-driver\[.\]hsc\[.\]gov\[.\]ua                                                                     | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of wanted\[.\]mvs\[.\]gov\[.\]ua                                                                       | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of minregeion\[.\]gov\[.\]ua                                                                           | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of health\[.\]mia\[.\]solutions                                                                        | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mtsbu\[.\]ua                                                                                        | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of motorsich\[.\]com                                                                                   | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of kyivcity\[.\]com                                                                                    | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of bdr\[.\]mvs\[.\]gov\[.\]ua                                                                          | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of gkh\[.\]in\[.\]ua                                                                                   | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of kmu\[.\]gov\[.\]ua                                                                                  | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mon\[.\]gov\[.\]ua                                                                                  | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of minagro\[.\]gov\[.\]ua                                                                              | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| FreeCivilian    | UA data sharing | DB of mfa\[.\]gov\[.\]ua                                                                                  | No        | TA discussion in past 90 days | FreeCivilian .onion \[not linked\]                         |
| Intel\_Data     | UA data sharing | PII DB (56M) of Ukrainian Citizens                                                                        | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| Kristina        | UA data sharing | DB of Ukrainian National Police (mvs\[.\]gov\[.\]ua)                                                      | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| NetSec          | UA data sharing | PII DB (53M) of Ukrainian citizens                                                                        | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| Psycho\_Killer  | UA data sharing | PII DB (56M) of Ukrainian Citizens                                                                        | No        | TA discussion in past 90 days | Exploit Forum .onion \[not linked\]                        |
| Sp333           | UA data sharing | PII DB of Ukrainian and Russian interpreters, translators, and tour guides                                | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| Vaticano        | UA data sharing | DB of Ukrainian 'Diia' e-Governance Portal for Ministry of Digital Transformation of Ukraine \[copy\]     | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |
| Vaticano        | UA data sharing | DB of Ministry for Communities and Territories Development of Ukraine (minregion\[.\]gov\[.\]ua) \[copy\] | No        | TA discussion in past 90 days | RaidForums \[not linked; site hijacked since UA invasion\] |

#### `Vendor Support`
| Vendor | Offering | URL |
| --- | --- | --- |
| Dragos | Access to Dragos service if from US/UK/ANZ and in need of ICS cybersecurity support | [twitter.com/RobertMLee](https://twitter.com/RobertMLee/status/1496862093588455429) |
| GreyNoise |  Any and all `Ukrainian` emails registered to GreyNoise have been upgraded to VIP which includes full, uncapped enterprise access to all GreyNoise products. There is a landing page for GreyNoise data at [https://www.greynoise.io/viz/pulse](https://www.greynoise.io/viz/pulse) | [twitter.com/Andrew___Morris](https://twitter.com/Andrew___Morris/status/1496923545712091139) |
| Recorded Future | Providing free intelligence-driven insights, perspectives, and mitigation strategies as the situation in Ukraine evolves| [recordedfuture.com](https://www.recordedfuture.com/ukraine/) |
| Flashpoint | Free Access to Flashpoint’s Latest Threat Intel on Ukraine | [go.flashpoint-intel.com](https://go.flashpoint-intel.com/trial/access/30days) |
| ThreatABLE | A Ukraine tag for free threat intelligence feed that's more highly curated to cyber| [twitter.com/threatable](https://twitter.com/threatable/status/1497233721803644950) |
| Orange | IOCs related to Russia-Ukraine 2022 conflict extracted from our Datalake Threat Intelligence platform. | [github.com/Orange-Cyberdefense](https://github.com/Orange-Cyberdefense/russia-ukraine_IOCs)|
| FSecure | F-Secure FREEDOME VPN is now available for free in all of Ukraine | [twitter.com/FSecure](https://twitter.com/FSecure/status/1497248407303462960) |
| Multiple vendors | List of vendors offering their services to Ukraine for free, put together by [@chrisculling](https://twitter.com/chrisculling/status/1497023038323404803) | [docs.google.com/spreadsheets](https://docs.google.com/spreadsheets/d/18WYY9p1_DLwB6dnXoiiOAoWYD8X0voXtoDl_ZQzjzUQ/edit#gid=0) |
| Mandiant | Free threat intelligence, webinar and guidance for defensive measures relevant to the situation in Ukraine. | [mandiant.com](https://www.mandiant.com/resources/insights/ukraine-crisis-resource-center) |
| Starlink | Satellite internet constellation operated by SpaceX providing satellite Internet access coverage to Ukraine | [twitter.com/elonmusk](https://twitter.com/elonmusk/status/1497701484003213317) |
| Romania DNSC | Romania’s DNSC – in partnership with Bitdefender – will provide technical consulting, threat intelligence and, free of charge, cybersecurity technology to any business, government institution or private citizen of Ukraine for as long as it is necessary. | [Romania's DNSC Press Release](https://dnsc.ro/citeste/press-release-dnsc-and-bitdefender-work-together-in-support-of-ukraine)|
| BitDefender | Access to Bitdefender technical consulting, threat intelligence and both consumer and enterprise cybersecurity technology | [bitdefender.com/ukraine/](https://www.bitdefender.com/ukraine/) |
| NameCheap | Free anonymous hosting and domain name registration to any anti-Putin anti-regime and protest websites for anyone located within Russia and Belarus | [twitter.com/Namecheap](https://twitter.com/Namecheap/status/1498998414020861953) |
| Avast | Free decryptor for PartyTicket ransomware | [decoded.avast.io](https://decoded.avast.io/threatresearch/help-for-ukraine-free-decryptor-for-hermeticransom-ransomware/) |
| Recorded Future | Insikt Group’s list of indicators of compromise associated with threat actors and malware related to the Russian cyber actions against Ukraine | [recordedfuture.com](https://www.recordedfuture.com/ukraine/) |
| CybelAngel | CybelAngel offers its services to interested NGOs active in the war at no cost, to minimize the risks of their missions being interrupted by cyber attacks. CybelAngel also offers Ukrainian companies an assessment of their digital exposure in the region at no charge. | [cybelangel.com](https://cybelangel.com/blog/message-on-ukraine/) |
| Malware Patrol | Free 6 months DNS Firewall service subscription for Ukraine-based companies and goverment entities | [www.linkedin.com](https://www.linkedin.com/feed/update/urn:li:activity:6903059206522712064/)

#### `Vetted OSINT Sources`
| Handle | Affiliation |
| --- | --- |
| [@KyivIndependent](https://twitter.com/KyivIndependent) | English-language journalism in Ukraine |
| [@IAPonomarenko](https://twitter.com/IAPonomarenko) | Defense reporter with The Kyiv Independent |
| [@KyivPost](https://twitter.com/KyivPost) | English-language journalism in Ukraine |
| [@Shayan86](https://twitter.com/Shayan86) | BBC World News Disinformation journalist |
| [@Liveuamap](https://twitter.com/Liveuamap) | Live Universal Awareness Map (“Liveuamap”) independent global news and information site |
| [@DAlperovitch](https://twitter.com/DAlperovitch) | The Alperovitch Institute for Cybersecurity Studies, Founder & Former CTO of CrowdStrike |
| [@COUPSURE](https://twitter.com/COUPSURE) | OSINT investigator for Centre for Information Resilience |
| [@netblocks](https://twitter.com/netblocks) | London-based Internet's Observatory |


#### `Miscellaneous Resources`
| Source | URL | Content |
| --- | --- | --- |
| PowerOutages.com | https://poweroutage.com/ua | Tracking PowerOutages across Ukraine |
| Monash IP Observatory | https://twitter.com/IP_Observatory | Tracking IP address outages across Ukraine |
| Project Owl Discord | https://discord.com/invite/projectowl | Tracking foreign policy, geopolitical events, military and governments, using a Discord-based crowdsourced approach, with a current emphasis on Ukraine and Russia |
| russianwarchatter.info | https://www.russianwarchatter.info/ | Known Russian Military Radio Frequencies |
| UT CREEES | https://liberalarts.utexas.edu/slavic/resources/ukraine-conflict-resources.php | Compiled resources to help understand the Russian invasion of Ukraine, with links to resources, action items, and academic sources

### Note:

Curated Intel `does not` support, encourage, partake, or condone hacking, attacking or targeting users of any kind. This information is `clearly` meant to `help` cybersecurity teams `supporting Ukraine` still doing their jobs while dealing with the Russian invasion.
