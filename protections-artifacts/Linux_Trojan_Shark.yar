rule Linux_Trojan_Shark_b918ab75 {
    meta:
        id = "4sz7AKoXUM4UVhGhYBS8VY"
        fingerprint = "v1_sha256_16302c29f2ae4109b8679933eb7fd9ef9306b0c215f20e8fff992b0b848974a9"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Shark"
        reference_sample = "8b6fe9f496996784e42b75fb42702aa47aefe32eac6f63dd16a0eb55358b6054"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 26 00 C7 46 14 0A 00 00 00 C7 46 18 15 00 00 00 EB 30 C7 46 14 04 00 }
    condition:
        all of them
}

