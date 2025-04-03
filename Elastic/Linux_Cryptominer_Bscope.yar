rule Linux_Cryptominer_Bscope_348b7fa0 {
    meta:
        id = "1xjO7NlGZyFUhhgLKw0gLt"
        fingerprint = "v1_sha256_bc6a59dcc36676273c61fa71231fd8709884beebb7ab64b58f22551393b20c71"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Bscope"
        reference_sample = "a6fb80d77986e00a6b861585bd4e573a927e970fb0061bf5516f83400ad7c0db"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 04 8B 00 03 45 C0 89 02 8B 45 08 8D 50 08 8B 45 08 83 C0 08 }
    condition:
        all of them
}

