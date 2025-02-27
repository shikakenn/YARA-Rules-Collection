rule Linux_Trojan_Torii_fa253f2a {
    meta:
        id = "7MjIc5n7SNc31jFJTQz3Yq"
        fingerprint = "v1_sha256_d99ed4dc1fc2905da03d9ed4288de621d8287af98357560948c7746bf05c99fd"
        version = "1.0"
        date = "2022-01-05"
        modified = "2022-01-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Torii"
        reference_sample = "19004f250b578b3b53273e8426285df2030fac0aee3227ef98e7fcbf2a8acb86"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 69 6D 65 00 47 4C 49 42 43 5F 32 2E 31 34 00 47 4C 49 42 43 5F }
    condition:
        all of them
}

