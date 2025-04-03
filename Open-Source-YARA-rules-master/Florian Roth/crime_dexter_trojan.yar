rule Dexter_Malware {
    meta:
        id = "3spSoJ7JPqesh92AgRMsYu"
        fingerprint = "v1_sha256_4a98c8c49b25cfba6428c433fc2768669bd252f1ea7b2205356c93433249f464"
        version = "1.0"
        score = 70
        date = "2015/02/10"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects the Dexter Trojan/Agent http://goo.gl/oBvy8b"
        category = "INFO"
        reference = "http://goo.gl/oBvy8b"

    strings:
        $s0 = "Java Security Plugin" fullword wide
        $s1 = "%s\\%s\\%s.exe" fullword wide
        $s2 = "Sun Java Security Plugin" fullword wide
        $s3 = "\\Internet Explorer\\iexplore.exe" fullword wide
    condition:
        all of them
}
