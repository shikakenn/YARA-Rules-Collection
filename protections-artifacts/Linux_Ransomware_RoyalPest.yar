rule Linux_Ransomware_RoyalPest_502a3db6 {
    meta:
        id = "2OdIH9ZmdSfEn7TMbZgm2"
        fingerprint = "v1_sha256_aefb5a286636b827b50e4bc0ea978a75ba6a9e572504bfbc0a7700372c54a077"
        version = "1.0"
        date = "2023-07-27"
        modified = "2024-02-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.RoyalPest"
        reference_sample = "09a79e5e20fa4f5aae610c8ce3fe954029a91972b56c6576035ff7e0ec4c1d14"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a1 = "hit by Royal ransomware."
        $a2 = "Please contact us via :"
        $a3 = ".onion/%s"
        $a4 = "esxcli vm process list > list"
    condition:
        3 of them
}

