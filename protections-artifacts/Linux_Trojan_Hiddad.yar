rule Linux_Trojan_Hiddad_e35bff7b {
    meta:
        id = "3HoBLhbRTrL2mH2aVwFIpx"
        fingerprint = "v1_sha256_3881222807585dc933cb61473751d13297fa7eb085a50d435d3b680354a35ee9"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Trojan.Hiddad"
        reference_sample = "22a418e660b5a7a2e0cc1c1f3fe1d150831d75c4fedeed9817a221194522efcf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 3C 14 48 63 CF 89 FE 48 69 C9 81 80 80 80 C1 FE 1F 48 C1 E9 20 }
    condition:
        all of them
}

