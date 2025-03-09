rule FE_APT_Tool_Linux_CLEANPULSE_2 
{ 
    meta:
        id = "3f57hiqaRhOFZnaTbFLPjc"
        fingerprint = "v1_sha256_a394e54bd5763b3828a8dbcda82ea7a252b7ed44b448ab5dd0092048db6e946e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Mandiant"
        description = "NA"
        category = "INFO"
        date_created = "2021-05-17"
        sha256 = "9308cfbd697e4bf76fcc8ff71429fbdfe375441e8c8c10519b6a73a776801ba7"
        reference_url = "https://www.fireeye.com/blog/threat-research/2021/05/updates-on-chinese-apt-compromising-pulse-secure-vpn-devices.html"

    strings: 
        $sb1 = { 00 89 4C 24 08 FF 52 04 8D 00 } 
        $ss1 = "\x00OK!\x00" 
        $ss2 = "\x00argv %d error!\x00" 
        $ss3 = "\x00ptrace_write\x00" 
        $ss4 = "\x00ptrace_attach\x00" 
    condition: 
        (uint32(0) == 0x464c457f) and all of them 
}
