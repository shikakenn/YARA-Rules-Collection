rule Linux_Trojan_Mech_d30ec0a0 {
    meta:
        id = "44kh08KjKZVPhVXz2SpASs"
        fingerprint = "v1_sha256_268aeb25d6468412d8123bab5eb2c8bd7704828d0ef3c3d771aa036e374127d7"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Mech"
        reference_sample = "710d1a0a8c7eecc6d793933c8a97cec66d284b3687efee7655a2dc31d15c0593"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6E 63 20 2D 20 4C 69 6E 75 78 20 32 2E 32 2E 31 }
    condition:
        all of them
}

