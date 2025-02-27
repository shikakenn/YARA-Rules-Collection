rule Windows_Trojan_Limerat_24269a79 {
    meta:
        id = "7JyZ4AHaPfnJnj5T6Hzm93"
        fingerprint = "v1_sha256_053a6abe589db23c4b9baed24729c8bcdd9019535fd0d9efc60ab4035c9779f3"
        version = "1.0"
        date = "2021-08-17"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Limerat"
        reference_sample = "ec781a714d6bc6fac48d59890d9ae594ffd4dbc95710f2da1f1aa3d5b87b9e01"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr \"'" wide fullword
    condition:
        all of them
}

