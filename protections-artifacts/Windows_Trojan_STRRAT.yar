rule Windows_Trojan_STRRAT_a3e48cd2 {
    meta:
        id = "4oawFeyTcANE6wfX4zWP8g"
        fingerprint = "v1_sha256_32f79695829f703bf9996d212aeb563791aed28e1bbb9f700cb45325fd02db77"
        version = "1.0"
        date = "2024-03-13"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.STRRAT"
        reference_sample = "97e67ac77d80d26af4897acff2a3f6075e0efe7997a67d8194e799006ed5efc9"
        severity = 100
        arch_context = "x86"
        scan_context = "memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "strigoi/server/ping.php?lid="
        $str2 = "/strigoi/server/?hwid="
    condition:
        all of them
}

