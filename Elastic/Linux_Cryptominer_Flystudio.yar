rule Linux_Cryptominer_Flystudio_579a3a4d {
    meta:
        id = "10veHfw0hicr9P8JQmgnZ5"
        fingerprint = "v1_sha256_6579630a4fb6cf5bc8ccb2e4f93f5d549baa6ea9b742b2ee83a52f07352c4741"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Flystudio"
        reference_sample = "84afc47554cf42e76ef8d28f2d29c28f3d35c2876cec2fb1581b0ac7cfe719dd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { EF C1 66 0F 72 F1 05 66 0F EF C2 66 0F EF C1 66 0F 6F CD 66 0F }
    condition:
        all of them
}

rule Linux_Cryptominer_Flystudio_0a370634 {
    meta:
        id = "2YE8KMpDTAPdX8VeqN2vO7"
        fingerprint = "v1_sha256_cf924ba45a7dba19fe571bb9da8c4896690c3ad02f732b759a10174b9f61883f"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Flystudio"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 72 D7 19 66 41 0F EF E9 66 0F EF EF 66 0F 6F FD 66 41 0F FE FD 66 44 0F }
    condition:
        all of them
}

