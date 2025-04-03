rule Linux_Trojan_Dropperl_b97baf37 {
    meta:
        id = "7lF15pKxVMNICwpX14K3Cb"
        fingerprint = "v1_sha256_e58130c33242bc3020602c2c0254bed2bbc564c4a11806c6cfcd858fd724c362"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "aff94f915fc81d5a2649ebd7c21ec8a4c2fc0d622ec9b790b43cc49f7feb83da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 12 48 89 10 83 45 DC 01 83 45 D8 01 8B 45 D8 3B 45 BC 7C CF 8B }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_e2443be5 {
    meta:
        id = "3KZztD3S54p1QQckIflVrw"
        fingerprint = "v1_sha256_85733ff904cfa3eddaa4c4fbfc51c00494c3a3725e2eb722bbf33c82e7135336"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "aff94f915fc81d5a2649ebd7c21ec8a4c2fc0d622ec9b790b43cc49f7feb83da"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 F0 75 DB EB 17 48 8B 45 F8 48 83 C0 08 48 8B 10 48 8B 45 F8 48 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_683c2ba1 {
    meta:
        id = "1YDOkobg8TlbTIPzZgSuTk"
        fingerprint = "v1_sha256_eef2bdef7e20633f7dc92f653b43e3a217e8cbdbac63d05540bdd520e22dd1ed"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "a02e166fbf002dd4217c012f24bb3a8dbe310a9f0b0635eb20a7d315049367e1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_8bca73f6 {
    meta:
        id = "5uwIwEXYZ8q4Z21soBig8T"
        fingerprint = "v1_sha256_2cfad4e436198391185fdae5c4af18ae43841db19da33473fdf18b64b0399613"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "e7c17b7916b38494b9a07c249acb99499808959ba67125c29afec194ca4ae36c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 95 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 62 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_c4018572 {
    meta:
        id = "645mKWxOdPzHdRiPmsjRZX"
        fingerprint = "v1_sha256_10d70540532c5c2984dc7e492672450924cb8f34c8158638191886057596b0a1"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "c1515b3a7a91650948af7577b613ee019166f116729b7ff6309b218047141f6d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 97 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_733c0330 {
    meta:
        id = "byts8khm7pUMcGDSIdOLx"
        fingerprint = "v1_sha256_37bf7777e26e556f09b8cb0e7e3c8425226a6412c3bed0d95fdab7229b6f4815"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "b303f241a2687dba8d7b4987b7a46b5569bd2272e2da3e0c5e597b342d4561b6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 A0 FB FF FF 83 7D DC 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

rule Linux_Trojan_Dropperl_39f4cd0d {
    meta:
        id = "Y7JrOpdIajHFtQP8tNhv8"
        fingerprint = "v1_sha256_5b61f54604b110d2c8efaf1782a2e520baac96c6d3e8d1eda0877475c504bf89"
        version = "1.0"
        date = "2021-04-06"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dropperl"
        reference_sample = "c08e1347877dc77ad73c1e017f928c69c8c78a0e3c16ac5455668d2ad22500f3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { E8 ?? FA FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }
    condition:
        all of them
}

