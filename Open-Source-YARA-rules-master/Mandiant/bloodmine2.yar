rule FE_APT_Tool_Linux_BLOODMINE_2 
{ 
    meta:
        id = "46lA723Sy3VykAeAKlG4lv"
        fingerprint = "v1_sha256_a95c8eb15af57f0328d3d86c580924cf9e5b62a51f3977a969d6341f54dea206"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Mandiant"
        description = "NA"
        category = "INFO"
        date_created = "2021-05-17"
        sha256 = "38705184975684c826be28302f5e998cdb3726139aad9f8a6889af34eb2b0385"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"

    strings: 
        $ss1 = "\x00[+]\x00" 
        $ss2 = "\x00%d-%d-%d-%d-%d-%d\x0a\x00" 
        $ss3 = "\x00[+]The count of saved logs: %d\x0a\x00" 
        $ss4 = "\x00[+]Remember to clear \"%s\", good luck!\x0a\x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}
