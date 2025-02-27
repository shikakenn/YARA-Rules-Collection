rule Linux_Trojan_Dnsamp_c31eebd4 {
    meta:
        id = "UlJMkbnDrbXOMX3FFmfgG"
        fingerprint = "v1_sha256_b998065eff9f67a1cdf19644a13edb0cef3c619d8b6e16c412d58f5d538e4617"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Dnsamp"
        reference_sample = "4b86de97819a49a90961d59f9c3ab9f8e57e19add9fe1237d2a2948b4ff22de6"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 45 F8 8B 40 14 48 63 D0 48 8D 45 E0 48 8D 70 04 48 8B 45 F8 48 8B }
    condition:
        all of them
}

