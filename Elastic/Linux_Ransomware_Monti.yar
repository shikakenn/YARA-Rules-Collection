rule Linux_Ransomware_Monti_9c64f016 {
    meta:
        id = "2spowN9ZxtpxNIdjWZ0RlD"
        fingerprint = "v1_sha256_c22a4efaaf97d68deaf1978e637dd7f790541e5007c6323629bcc9e3d4eecd06"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Monti"
        reference_sample = "ad8d1b28405d9aebae6f42db1a09daec471bf342e9e0a10ab4e0a258a7fa8713"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "[%s] Flag doesn't equal MONTI."
        $a2 = "--vmkill Whether to kill the virtual machine"
        $a3 = "MONTI strain."
        $a4 = "http://monti"
    condition:
        2 of them
}

