rule Windows_Trojan_PoshC2_e2d3881e {
    meta:
        id = "7gvBb1iX0LqjDuIjJfgYfX"
        fingerprint = "v1_sha256_4f3e2a9f22826a155a3007193a0f75a5fde6e423734a60f30628ea3bb33d3457"
        version = "1.0"
        date = "2023-03-29"
        modified = "2023-04-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.PoshC2"
        reference_sample = "7a718a4f74656346bd9a2e29e008705fc2b1c4d167a52bd4f6ff10b3f2cd9395"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Sharp_v4_x64.dll"
        $a2 = "Sharp_v4_x86_dll"
        $a3 = "Posh_v2_x64_Shellcode" wide
        $a4 = "Posh_v2_x86_Shellcode" wide
        $b1 = "kill-implant" wide
        $b2 = "run-dll-background" wide
        $b3 = "run-exe-background" wide
        $b4 = "TVqQAAMAAAAEAAAA"
    condition:
        1 of ($a*) and 1 of ($b*)
}

