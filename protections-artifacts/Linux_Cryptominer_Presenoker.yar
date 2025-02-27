rule Linux_Cryptominer_Presenoker_3bb5533d {
    meta:
        id = "736maZH8lJgadxqQ7kZ9I7"
        fingerprint = "v1_sha256_13bf69ea6bc7df5ba9ebffe67234657f2ecab99e28fd76d0bbedceaf9706a4dd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Presenoker"
        reference_sample = "bbc155c610c7aa439f98e32f97895d7eeaef06dab7cca05a5179b0eb3ba3cc00"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 47 10 74 72 F3 0F 6F 00 66 0F 7E C2 0F 29 04 24 85 D2 F3 0F 6F }
    condition:
        all of them
}

