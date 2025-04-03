rule Windows_Ransomware_Mespinoza_3adb59f5 {
    meta:
        id = "6IP2g5UlFh4znuT8vqqPYu"
        fingerprint = "v1_sha256_28c8ad42a3af70fed274edc9105dae5cef13749d71510561a50428c822464934"
        version = "1.0"
        date = "2021-08-05"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Mespinoza"
        reference_sample = "6f3cd5f05ab4f404c78bab92f705c91d967b31a9b06017d910af312fa87ae3d6"
        severity = 90
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Don't try to use backups because it were encrypted too." ascii fullword
        $a2 = "Every byte on any types of your devices was encrypted." ascii fullword
        $a3 = "n.pysa" wide fullword
    condition:
        all of them
}

