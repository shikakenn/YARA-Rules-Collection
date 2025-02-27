rule Linux_Trojan_Sysrv_85097f24 {
    meta:
        id = "4WYXnPlhPP7koN8A7FEGCE"
        fingerprint = "v1_sha256_96bee8b9b0e9c2afd684582301f9e110fd08fcabaea798bfb6259a4216f69be1"
        version = "1.0"
        date = "2021-06-28"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "17fbc8e10dea69b29093fcf2aa018be4d58fe5462c5a0363a0adde60f448fb26"
        threat_name = "Linux.Trojan.Sysrv"
        severity = "100"
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 32 26 02 0F 80 0C 0A FF 0B 02 02 22 04 2B 02 16 02 1C 01 0C 09 }
    condition:
        all of them
}

