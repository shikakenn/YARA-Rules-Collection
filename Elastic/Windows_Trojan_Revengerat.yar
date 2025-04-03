rule Windows_Trojan_Revengerat_db91bcc6 {
    meta:
        id = "4yzkrLc3zSB3LJHxBmVic0"
        fingerprint = "v1_sha256_1e33cb1d614aae0b2181ebaca694c69e7fc849b3a3b7ffff7059e8c43553f8cc"
        version = "1.0"
        date = "2021-09-02"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Revengerat"
        reference_sample = "30d8f81a19976d67b495eb1324372598cc25e1e69179c11efa22025341e455bd"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Revenge-RAT" wide fullword
        $a2 = "SELECT * FROM FirewallProduct" wide fullword
        $a3 = "HKEY_CURRENT_USER\\SOFTWARE\\" wide fullword
        $a4 = "get_MachineName" ascii fullword
    condition:
        all of them
}

