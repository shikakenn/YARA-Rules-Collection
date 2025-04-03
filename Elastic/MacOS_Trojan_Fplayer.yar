rule MacOS_Trojan_Fplayer_1c1fae37 {
    meta:
        id = "6cEcDCYWxreu3B0rlRh29G"
        fingerprint = "v1_sha256_0d65717bdbac694ffb2535a1ff584f7ec2aa7b553a08d29113c6e2bd7b2ff1aa"
        version = "1.0"
        date = "2021-10-05"
        modified = "2021-10-25"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "MacOS.Trojan.Fplayer"
        reference_sample = "f57e651088dee2236328d09705cef5e98461e97d1eb2150c372d00ca7c685725"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"

    strings:
        $a = { 56 41 55 41 54 53 48 83 EC 48 4D 89 C4 48 89 C8 48 89 D1 49 89 F6 49 89 FD 49 }
    condition:
        all of them
}

