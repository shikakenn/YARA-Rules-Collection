rule Linux_Trojan_Marut_47af730d {
    meta:
        id = "xMQZXeIjoeoyXorKJ3cxW"
        fingerprint = "v1_sha256_048ce8059be6697c5f507fb1912ac2adcedab87c75583dd84700984e6d0d81e6"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Marut"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 20 89 34 24 FF D1 8B 44 24 0C 0F B6 4C 24 04 8B 54 24 08 85 D2 }
    condition:
        all of them
}

