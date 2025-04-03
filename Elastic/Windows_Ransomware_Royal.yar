rule Windows_Ransomware_Royal_b7d42109 {
    meta:
        id = "47iX8zB4BEuucinyOSK3Mn"
        fingerprint = "v1_sha256_06f4a1487e97e0b8c1f5df380ab4f90b37ef0a508aba7dac272c16c8371d8143"
        version = "1.0"
        date = "2022-11-04"
        modified = "2022-12-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Royal"
        reference_sample = "491c2b32095174b9de2fd799732a6f84878c2e23b9bb560cd3155cbdc65e2b80"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Try Royal today and enter the new era of data security" ascii fullword
        $a2 = "If you are reading this, it means that your system were hit by Royal ransomware." ascii fullword
        $a3 = "http://royal"
        $a4 = "\\README.TXT" wide fullword
    condition:
        all of them
}

