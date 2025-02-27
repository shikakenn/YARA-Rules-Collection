rule Linux_Trojan_Godropper_bae099bd {
    meta:
        id = "65DZtuMNDf50cMXwU7loO2"
        fingerprint = "v1_sha256_ef6274928f7cfc0312122ac3e4153fb0a78dc7d5fb2d68db6cbe4974f5497210"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Godropper"
        reference_sample = "704643f3fd11cda1d52260285bf2a03bccafe59cfba4466427646c1baf93881e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { FF FF FF FF 88 DB A2 31 03 A3 5A 5C 9A 19 0E DB }
    condition:
        all of them
}

