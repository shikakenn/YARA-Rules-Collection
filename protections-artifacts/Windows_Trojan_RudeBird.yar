rule Windows_Trojan_RudeBird_3cbf7bc6 {
    meta:
        id = "2BInHlcnJRnaWhM1ueMbjX"
        fingerprint = "v1_sha256_2095c3b6bde779b5661c7796b5e33bb0c43facf791b272a603b786f889a06a95"
        version = "1.0"
        date = "2023-05-09"
        modified = "2023-06-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/introducing-the-ref5961-intrusion-set"
        threat_name = "Windows.Trojan.RudeBird"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 40 53 48 83 EC 20 48 8B D9 B9 D8 00 00 00 E8 FD C1 FF FF 48 8B C8 33 C0 48 85 C9 74 05 E8 3A F2 }
    condition:
        all of them
}

