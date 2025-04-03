rule Windows_Trojan_Gh0st_ee6de6bc {
    meta:
        id = "53aOrGJBm73RQhFuHWR2gx"
        fingerprint = "v1_sha256_3619df974c9f4ec76899afbafdfd6839070714862c7361be476cf8f83e766e2f"
        version = "1.0"
        date = "2021-06-10"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Identifies a variant of Gh0st Rat"
        category = "INFO"
        threat_name = "Windows.Trojan.Gh0st"
        reference_sample = "ea1dc816dfc87c2340a8b8a77a4f97618bccf19ad3b006dce4994be02e13245d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = ":]%d-%d-%d  %d:%d:%d" ascii fullword
        $a2 = "[Pause Break]" ascii fullword
        $a3 = "f-secure.exe" ascii fullword
        $a4 = "Accept-Language: zh-cn" ascii fullword
    condition:
        all of them
}

