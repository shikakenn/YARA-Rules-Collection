rule Linux_Trojan_Pumakit_b86138c3 {
    meta:
        id = "4eOAKyd0lRe0JqZXPzi4IM"
        fingerprint = "v1_sha256_fc486aafee5cd4156ef7027ed6bf596c62397601787833d9173c198d5d919cde"
        version = "1.0"
        date = "2024-12-09"
        modified = "2024-12-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Pumakit"
        reference_sample = "30b26707d5fb407ef39ebee37ded7edeea2890fb5ec1ebfa09a3b3edfc80db1f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str1 = "PUMA %s"
        $str2 = "Kitsune PID %ld"
        $str3 = "/usr/share/zov_f"
        $str4 = "zarya"
        $str5 = ".puma-config"
        $str6 = "ping_interval_s"
        $str7 = "session_timeout_s"
        $str8 = "c2_timeout_s"
        $str9 = "LD_PRELOAD=/lib64/libs.so"
        $str10 = "kit_so_len"
        $str11 = "opsecurity1.art"
        $str12 = "89.23.113.204"
    condition:
        4 of them
}

