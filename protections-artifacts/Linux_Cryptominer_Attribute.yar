rule Linux_Cryptominer_Attribute_3683d149 {
    meta:
        id = "1Cp9ivrwE7kXO36HgcbUqq"
        fingerprint = "v1_sha256_71aa8aa4171671af4aa0271b64da95ac1d8766de12a949c97ebcac9369224ecd"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Attribute"
        reference_sample = "ec9e74d52d745275718fe272bfd755335739ad5f680f73f5a4e66df6eb141a63"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 74 6F 20 66 61 73 74 29 20 6F 72 20 39 20 28 61 75 74 6F }
    condition:
        all of them
}

