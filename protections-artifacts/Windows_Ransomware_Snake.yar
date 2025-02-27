rule Windows_Ransomware_Snake_550e0265 : beta {
    meta:
        id = "53roQQGlBBU9z52f2fHkqK"
        fingerprint = "v1_sha256_d9c2f6961a4ef560743060ed176bdc606561ca1b8270b8826cb0dbadaf4e5dbc"
        version = "1.0"
        date = "2020-06-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies SNAKE ransomware"
        category = "INFO"
        reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
        threat_name = "Windows.Ransomware.Snake"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Go build ID: \"X6lNEpDhc_qgQl56x4du/fgVJOqLlPCCIekQhFnHL/rkxe6tXCg56Ez88otHrz/Y-lXW-OhiIbzg3-ioGRz\"" ascii fullword
        $a2 = "We breached your corporate network and encrypted the data on your computers."
        $a3 = "c:\\users\\public\\desktop\\Fix-Your-Files.txt" nocase
        $a4 = "%System Root%\\Fix-Your-Files.txt" nocase
        $a5 = "%Desktop%\\Fix-Your-Files.txt" nocase
    condition:
        1 of ($a*)
}

rule Windows_Ransomware_Snake_119f9c83 : beta {
    meta:
        id = "1AGYOijYaQRgpn5cLMGMkI"
        fingerprint = "v1_sha256_cf6c81e7332acc798409a05a548460bad0ac3621402672c242e48a1b6bccdae6"
        version = "1.0"
        date = "2020-06-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies SNAKE ransomware"
        category = "INFO"
        reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
        threat_name = "Windows.Ransomware.Snake"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $c1 = { 00 40 83 7C 00 40 9E 7C 00 60 75 7C 00 B0 6C 7C 00 B0 74 7C 00 D0 74 7C 00 B0 59 7C 00 D0 59 7C 00 F0 59 7C 00 10 5A 7C 00 30 5A 7C 00 50 5A 7C 00 70 5A 7C 00 90 5A 7C 00 B0 5A 7C 00 D0 5A 7C 00 D0 6C 7C 00 F0 5A 7C 00 30 5B 7C 00 50 5B 7C 00 70 5B 7C 00 90 5B 7C 00 D0 5E 7C 00 B0 5B 7C 00 D0 5B 7C 00 F0 5B 7C 00 50 60 7C 00 70 61 7C 00 10 5C 7C 00 30 5C 7C 00 50 5C 7C 00 10 63 7C 00 70 5C 7C 00 90 5C 7C 00 90 64 7C 00 B0 5C 7C 00 F0 5C 7C 00 10 5D 7C 00 F0 6C 7C 00 10 6D 7C 00 30 5D 7C 00 50 5D 7C 00 30 6D 7C 00 90 71 7C 00 70 5D 7C 00 90 5D 7C 00 B0 5D 7C 00 D0 5D 7C 00 70 6D 7C 00 F0 5D 7C 00 10 5E 7C 00 30 5E 7C 00 50 5E 7C 00 70 5E 7C 00 90 5E 7C 00 B0 5E 7C 00 F0 5E 7C 00 10 5F 7C 00 30 5F 7C 00 50 5F 7C 00 70 5F 7C 00 90 6D 7C 00 90 5F 7C 00 B0 6D 7C 00 D0 6D 7C 00 F0 6D 7C 00 10 6E 7C 00 B0 5F 7C 00 D0 5F 7C 00 F0 5F 7C 00 10 60 7C 00 30 60 7C 00 30 6E 7C 00 70 60 7C }
        $c2 = { 00 30 64 7C 00 50 64 7C 00 70 64 7C 00 B0 64 7C 00 D0 64 7C 00 30 73 7C 00 F0 64 7C 00 90 71 7C 00 10 65 7C 00 30 65 7C 00 50 65 7C 00 90 72 7C 00 B0 72 7C 00 70 6E 7C 00 70 65 7C 00 B0 65 7C 00 D0 65 7C 00 F0 65 7C 00 10 66 7C 00 30 66 7C 00 50 66 7C 00 70 66 7C 00 90 66 7C 00 B0 66 7C 00 D0 66 7C 00 F0 66 7C 00 30 67 7C 00 90 6E 7C 00 B0 6E 7C 00 D0 6E 7C }
    condition:
        1 of ($c*)
}

