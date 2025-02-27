rule MacOS_Trojan_Aobokeylogger_bd960f34 {
    meta:
        id = "cd9vU79iUhPXA8r7YcXML"
        fingerprint = "v1_sha256_f89fbf1d6bf041de0ce32f7920818c34ce0eeb6779bb7fac6f223bbea1c6f6fa"
        version = "1.0"
        date = "2021-10-18"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Aobokeylogger"
        reference_sample = "2b50146c20621741642d039f1e3218ff68e5dbfde8bb9edaa0a560ca890f0970"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 20 74 68 61 6E 20 32 30 30 20 6B 65 79 73 74 72 6F 6B 65 73 20 }
    condition:
        all of them
}

