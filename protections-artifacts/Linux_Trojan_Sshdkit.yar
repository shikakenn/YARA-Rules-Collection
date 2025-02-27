rule Linux_Trojan_Sshdkit_18a0b82a {
    meta:
        id = "2i26PM0Czk0cTBBpDtDBt7"
        fingerprint = "v1_sha256_4b7a78ebf3c114809148cc9855379b2e63c959966272ad45759838d570b42016"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Sshdkit"
        reference_sample = "003245047359e17706e4504f8988905a219fcb48865afea934e6aafa7f97cef6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 06 2A CA 37 F2 31 18 0E 2F 47 CD 87 9D 16 3F 6D }
    condition:
        all of them
}

