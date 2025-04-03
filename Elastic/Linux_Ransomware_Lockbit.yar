rule Linux_Ransomware_Lockbit_d248e80e {
    meta:
        id = "7Ee49DomOfJFnlitlWWcsX"
        fingerprint = "v1_sha256_5d33d243cd7f9d9189139eb34a4dd8d81882be200223d5c8e60dfd07ca98f94b"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Lockbit"
        reference_sample = "4800a67ceff340d2ab4f79406a01f58e5a97d589b29b35394b2a82a299b19745"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "restore-my-files.txt" fullword
        $b1 = "xkeyboard-config" fullword
        $b2 = "bootsect.bak" fullword
        $b3 = "lockbit" fullword
        $b4 = "Error: %s" fullword
        $b5 = "crypto_generichash_blake2b_final" fullword
    condition:
        $a1 and 2 of ($b*)
}

rule Linux_Ransomware_Lockbit_5b30a04b {
    meta:
        id = "2azTNNk0TJExfudY8tdsiu"
        fingerprint = "v1_sha256_b89d0f25f08ffa35e075def6a29cf52a80500c6499732146426a71c741059a3b"
        version = "1.0"
        date = "2023-07-29"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Lockbit"
        reference_sample = "41cbb7d79388eaa4d6e704bd4a8bf8f34d486d27277001c343ea3ce112f4fb0d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = { 5D 50 4A 49 55 58 40 77 58 54 5C }
        $a2 = { 33 6B 5C 5A 4C 4B 4A 50 4F 5C 55 40 }
        $a3 = { 5E 4C 58 4B 58 57 4D 5C 5C 5D }
    condition:
        all of them
}

