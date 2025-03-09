rule FE_APT_Tool_Linux32_BLOODMINE_1 
{ 
    meta:
        id = "D8I6LSYTBIwWAgtdQSgz4"
        fingerprint = "v1_sha256_2243383c9ad86b2ff0204a3037c6306e1b34b57b52a75326cd18763ff87b52b3"
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
        $sb1 = { 6A 01 6A 03 68 [4] E8 [4-32] 50 E8 [4-32] 6A 01 5? 50 E8 [4-32] 50 E8 [4-32] 6A 01 5? 50 E8 [4-32] 6A 01 6A 01 68 [4] E8 [4-32] 8? [0-2] 01 A1 [4] 39 [2] 0F 8? }
        $sb2 = { 68 [4] FF B5 [4] E8 [4-16] 85 C0 7? ?? C7 05 [4] 01 00 00 00 E9 [4-32] 68 [4] FF B5 [4] E8 [4-16] 85 C0 7? ?? C7 05 [4] 02 00 00 00 E9 [4-32] 68 [4] FF B5 [4] E8 [4-16] 85 C0 7? ?? C7 05 [4] 03 00 00 00 E9 } 
    condition: 
        ((uint32(0) == 0x464c457f) and (uint8(4) == 1)) and all of them 
}
