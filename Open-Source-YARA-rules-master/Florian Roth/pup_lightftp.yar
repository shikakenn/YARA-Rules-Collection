
rule LightFTP_fftp_x86_64 {
    meta:
        id = "7MzU3WkUSb7yAuDyCTMLxH"
        fingerprint = "v1_sha256_f29a98a4014fc6c026aef4054bc2bee7bde2e9ad7f26f2368fdf0949f50847bb"
        version = "1.0"
        score = 50
        date = "2015-05-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a light FTP server"
        category = "INFO"
        reference = "https://github.com/hfiref0x/LightFTP"
        hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
        hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"

    strings:
        $s1 = "fftp.cfg" fullword wide
        $s2 = "220 LightFTP server v1.0 ready" fullword ascii
        $s3 = "*FTP thread exit*" fullword wide
        $s4 = "PASS->logon successful" fullword ascii
        $s5 = "250 Requested file action okay, completed." fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and 4 of them
}

rule LightFTP_Config {
    meta:
        id = "4dfG9ou7ydQLSEQzLjJcsQ"
        fingerprint = "v1_sha256_1e8c06dac9a5910816703ed15bef83116d9e2d9e612fda69697170ed98ee5f60"
        version = "1.0"
        date = "2015-05-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a light FTP server - config file"
        category = "INFO"
        reference = "https://github.com/hfiref0x/LightFTP"
        hash = "ce9821213538d39775af4a48550eefa3908323c5"

    strings:
        $s2 = "maxusers=" wide
        $s6 = "[ftpconfig]" fullword wide
        $s8 = "accs=readonly" fullword wide
        $s9 = "[anonymous]" fullword wide
        $s10 = "accs=" fullword wide
        $s11 = "pswd=" fullword wide
    condition:
        uint16(0) == 0xfeff and filesize < 1KB and all of them
}
