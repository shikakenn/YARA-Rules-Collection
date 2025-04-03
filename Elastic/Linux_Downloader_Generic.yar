rule Linux_Downloader_Generic_0bd15ae0 {
    meta:
        id = "6Qmuhp6UgVVkGVjTDOMV70"
        fingerprint = "v1_sha256_c9558562d9e9d3b55bd1fba9e55b332e6b4db5a170e0dd349bef1e35f0c7fd21"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Downloader.Generic"
        reference_sample = "e511efb068e76a4a939c2ce2f2f0a089ef55ca56ee5f2ba922828d23e6181f09"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 89 D0 83 C0 01 EB 05 B8 FF FF FF FF 48 8B 5D E8 64 48 33 1C 25 28 00 }
    condition:
        all of them
}

