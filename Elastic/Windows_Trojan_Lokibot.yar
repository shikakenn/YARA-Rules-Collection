rule Windows_Trojan_Lokibot_1f885282 {
    meta:
        id = "4eaJ3dwc1se6BXQ5wnEYVO"
        fingerprint = "v1_sha256_c76941a83e18f11ed5af701e89616d324ddba613a95069997ea8f1830f328307"
        version = "1.0"
        date = "2021-06-22"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Lokibot"
        reference_sample = "916eded682d11cbdf4bc872a8c1bcaae4d4e038ac0f869f59cc0a83867076409"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "MAC=%02X%02X%02XINSTALL=%08X%08Xk" fullword
    condition:
        all of them
}

rule Windows_Trojan_Lokibot_0f421617 {
    meta:
        id = "6oNyjyMTwZ5Xp9c01DVxid"
        fingerprint = "v1_sha256_0076ccbe43ae77e3a80164d43832643f077e659a595fff01c87694e2274c5e86"
        version = "1.0"
        date = "2021-07-20"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Lokibot"
        reference_sample = "de6200b184832e7d3bfe00c193034192774e3cfca96120dc97ad6fed1e472080"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a = { 08 8B CE 0F B6 14 38 D3 E2 83 C1 08 03 F2 48 79 F2 5F 8B C6 }
    condition:
        all of them
}

