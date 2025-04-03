rule Windows_Trojan_Kronos_cdd2e2c5 {
    meta:
        id = "72ST53qIiHU5qZJzGCEYhp"
        fingerprint = "v1_sha256_a8943c5ef166446629cb46517d35db39c97a1e3efa3a7a0b5cb3d3ee9d1e6e9c"
        version = "1.0"
        date = "2021-02-07"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Strings used by the Kronos banking trojan and variants."
        category = "INFO"
        reference = "https://www.virusbulletin.com/virusbulletin/2014/10/paper-evolution-webinjects"
        threat_name = "Windows.Trojan.Kronos"
        reference_sample = "baa9cedbbe0f5689be8f8028a6537c39e9ea8b0815ad76cb98f365ca5a41653f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "data_inject" ascii wide fullword
        $a2 = "set_filter" ascii wide fullword
        $a3 = "set_url" ascii wide fullword
        $a4 = "%ws\\%ws.cfg" ascii wide fullword
        $a5 = "D7T1H5F0F5A4C6S3" ascii wide fullword
        $a6 = "[DELETE]" ascii wide fullword
        $a7 = "Kronos" ascii wide fullword
    condition:
        4 of them
}

