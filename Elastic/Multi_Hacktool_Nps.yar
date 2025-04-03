rule Multi_Hacktool_Nps_c6eb4a27 {
    meta:
        id = "4uWYmhyGH8BbqvtRzPeKsS"
        fingerprint = "v1_sha256_53baf04f4ab8967761c6badb24f6632cc1bf4a448abf0049318b96855f30feea"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-01-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        threat_name = "Multi.Hacktool.Nps"
        reference_sample = "4714e8ad9c625070ca0a151ffc98d87d8e5da7c8ef42037ca5f43baede6cfac1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $str_info0 = "Reconnecting..."
        $str_info1 = "Loading configuration file %s successfully"
        $str_info2 = "successful start-up of local socks5 monitoring, port"
        $str_info3 = "successful start-up of local tcp monitoring, port"
        $str_info4 = "start local file system, local path %s, strip prefix %s ,remote port %"
        $str_info5 = "start local file system, local path %s, strip prefix %s ,remote port %s"
    condition:
        all of them
}

rule Multi_Hacktool_Nps_f76f257d {
    meta:
        id = "omjXHUvdEK0qzlAjvsrZi"
        fingerprint = "v1_sha256_0bbd7f86bfd2967dc390510c2e403d05e1b56551b965ea716b9e5330f75c9bd5"
        version = "1.0"
        date = "2024-01-24"
        modified = "2024-01-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/unmasking-financial-services-intrusion-ref0657"
        threat_name = "Multi.Hacktool.Nps"
        reference_sample = "80721b20a8667536a33fca50236f5c8e0c0d07aa7805b980e40818ab92cd9f4a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $string_decrypt_add = { 0F B6 BC 34 ?? ?? ?? ?? 44 0F B6 84 34 ?? ?? ?? ?? 44 01 C7 40 88 BC 34 ?? ?? ?? ?? 48 FF C6 }
        $string_decrypt_xor = { 0F B6 54 ?? ?? 0F B6 74 ?? ?? 31 D6 40 88 74 ?? ?? 48 FF C0 }
        $string_decrypt_sub = { 0F B6 94 04 ?? ?? ?? ?? 0F B6 B4 04 ?? ?? ?? ?? 29 D6 40 88 B4 04 ?? ?? ?? ?? 48 FF C0 }
        $NewJsonDb_str0 = { 63 6C 69 65 6E 74 73 2E 6A 73 6F 6E }
        $NewJsonDb_str1 = { 68 6F 73 74 73 2E 6A 73 6F 6E }
    condition:
        all of them
}

