rule Windows_PUP_Veriato_fae5978c {
    meta:
        id = "6LHZqs3VOjNLuQm1jJXg0g"
        fingerprint = "v1_sha256_8ae6f8b2b6e3849b33e6a477af52982efe137d7ebeff0c92cee5667d75f05145"
        version = "1.0"
        date = "2022-06-08"
        modified = "2022-09-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.PUP.Veriato"
        reference_sample = "53f09e60b188e67cdbf28bda669728a1f83d47b0279debf3d0a8d5176479d17f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "InitializeDll" fullword
        $a1 = "C:\\Windows\\winipbin\\svrltmgr.dll" fullword
        $a2 = "C:\\Windows\\winipbin\\svrltmgr64.dll" fullword
    condition:
        $s1 and ($a1 or $a2)
}

