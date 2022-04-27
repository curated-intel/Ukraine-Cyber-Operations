![logo](ci-logo.png)

# Ukraine-Cyber-Operations
Curated Intelligence is working with analysts from around the world to provide useful information to organisations in Ukraine looking for additional free threat intelligence. Slava Ukraini. Glory to Ukraine. ([Blog](https://www.curatedintel.org/2021/08/welcome.html) | [Twitter](https://twitter.com/CuratedIntel) | [LinkedIn](https://www.linkedin.com/company/curatedintelligence/))

### `Resources`
  - Timeline of Threat Reports
    - [January Threat Reports](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/Threat%20Reports/April.md)
    - [February Threat Reports](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/Threat%20Reports/February.md)
    - [March Threat Reports](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/Threat%20Reports/March.md)
    - [April Threat Reports](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/Threat%20Reports/April.md)
  - [Vendor Support](https://github.com/curated-intel/Ukraine-Cyber-Operations#vendor-support) 
  - [Vetted OSINT Sources](https://github.com/curated-intel/Ukraine-Cyber-Operations#vetted-osint-sources) 
  - [Miscellaneous Resources](https://github.com/curated-intel/Ukraine-Cyber-Operations#miscellaneous-resources) 
  - Equinix Threat Analysis Center (ETAC) contributions:
    - Contextualized [Indicators of Compromise (IOCs)](https://github.com/curated-intel/Ukraine-Cyber-Operations/tree/main/ETAC_IOCs) by ETAC `(Last updated 25 March 2022)`
    - Contextualized CERT-UA IOCs - see [here](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/ETAC_IOCs/CERT-UA_IOCs.csv) `(Last updated 28 March 2022)`
    - Vetted [YARA rule collection](https://github.com/curated-intel/Ukraine-Cyber-Operations/tree/main/yara) by ETAC `(Last updated 4 April 2022)`
    - Graphic of a Timeline of Russia-Ukraine Cyberwar `(Last updated 14 March 2022`)
    - Graphic of a Map of Russia-Ukraine Cyberwar `(Last updated 3 March 2022 `)
  - KPMG-Egyde Contributions: 
    - Added loosely-vetted [IOC Threat Hunt Feeds](https://github.com/curated-intel/Ukraine-Cyber-Operations/tree/main/KPMG-Egyde_Ukraine-Crisis_Feeds/MISP-CSV_MediumConfidence_Filtered) (h/t [0xDISREL](https://twitter.com/0xDISREL)) `(Last updated 7 April 2022)`
    - IOCs shared by these feeds are `LOW-TO-MEDIUM CONFIDENCE` we strongly recommend NOT adding them to a blocklist
    - These could potentially be used for `THREAT HUNTING` and could be added to a `WATCHLIST`
    - IOCs are generated in `MISP COMPATIBLE` CSV format
    - Additional [Threat Hunt Feed](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/KPMG-Egyde_Ukraine-Crisis_Feeds/MISP-CSV_LowConfidence_Unfiltered/Ukraine-Crisis_DomainTools_ThreatHunt_Feed.csv) for recently registered Ukrainian domain names (h/t DomainTools)
    - Additional [Threat Hunt Feed](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/KPMG-Egyde_Ukraine-Crisis_Feeds/MISP-CSV_MediumConfidence_Filtered/Ukraine-Crisis_RecordedFuture_ThreatHunt_Feed.csv) for threat groups targeting Ukraine (h/t RecordedFuture)
    - Ukrainain organizations offered by [Access and Data Brokers](https://github.com/curated-intel/Ukraine-Cyber-Operations/blob/main/access_data_brokers.md) on underground forums

### `Graphics by ETAC`

![timeline](UkraineTimelineUpdated.png)

![cyberwar](Russia-Ukraine%20Cyberwar.png)

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
| Malware Patrol | Free 6 months DNS Firewall service subscription for Ukraine-based companies and goverment entities | [www.linkedin.com](https://www.linkedin.com/feed/update/urn:li:activity:6903059206522712064/) |
| UnderDefense | UnderDefense is providing Managed Detection & Response services and incident repsonse support for Ukrainian critical infrastructure & government consulting in cybersecurity | [underdefense.com](https://underdefense.com/) |

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
| UT CREEES | https://liberalarts.utexas.edu/slavic/resources/ukraine-conflict-resources.php | Compiled resources to help understand the Russian invasion of Ukraine, with links to resources, action items, and academic sources |
| Telegram | https://t.me/s/itarmyofukraine2022 | IT ARMY of Ukraine |
| Telegram | https://t.me/s/cert_ua | Computer Emergency Response Team (CERT) of Ukraine |
| Telegram | https://t.me/SBUkr | Security Service of Ukraine (SBU) |

### Note:

Curated Intel `does not` support, encourage, partake, or condone hacking, attacking or targeting users of any kind. This information is `clearly` meant to `help` cybersecurity teams `supporting Ukraine` still doing their jobs while dealing with the Russian invasion.
