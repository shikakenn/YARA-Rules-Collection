rule Windows_PUP_Generic_198b73aa {
    meta:
        id = "77tG7p1zUZQWZdkIeTPHx"
        fingerprint = "v1_sha256_a584c34b9dfc2d78bf8a1e594a2ed519d20088184ce1df09e679b2400aa396d3"
        version = "1.0"
        date = "2023-07-27"
        modified = "2023-09-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.PUP.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "[%i.%i]av=[error]" fullword
        $a2 = "not_defined" fullword
        $a3 = "osver=%d.%d-ServicePack %d" fullword
    condition:
        all of them
}

