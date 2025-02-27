rule Linux_Ransomware_Esxiargs_75a8ec04 {
    meta:
        id = "7Q9AffqD6T6SUgvN3BlRxj"
        fingerprint = "v1_sha256_7316cab75c1bcf41ae6c96afa41ef96c37ab1bb679f36a0cc1dd08002a357165"
        version = "1.0"
        date = "2023-02-09"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.Esxiargs"
        reference_sample = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $s1 = "number of MB in encryption block"
        $s2 = "number of MB to skip while encryption"
        $s3 = "get_pk_data: key file is empty"
        $s4 = { 6F 70 65 6E 00 6C 73 65 65 6B 20 5B 65 6E 64 5D 00 6F 70 65 6E 5F 70 6B 5F 66 69 6C 65 }
        $s5 = "[<enc_step>] [<enc_size>] [<file_size>]"
    condition:
        3 of them
}

