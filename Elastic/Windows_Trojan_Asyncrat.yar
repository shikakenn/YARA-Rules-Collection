rule Windows_Trojan_Asyncrat_11a11ba1 {
    meta:
        id = "5wkae4wtXjUm0fQCXQUIdY"
        fingerprint = "v1_sha256_c6c4ce9ccf01c280be6c25c0c82c34b601626bc200b84d3e77b08be473335d3d"
        version = "1.0"
        date = "2021-08-05"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Asyncrat"
        reference_sample = "fe09cd1d13b87c5e970d3cbc1ebc02b1523c0a939f961fc02c1395707af1c6d1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" wide fullword
        $a2 = "Stub.exe" wide fullword
        $a3 = "get_ActivatePong" ascii fullword
        $a4 = "vmware" wide fullword
        $a5 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide fullword
        $a6 = "get_SslClient" ascii fullword
    condition:
        all of them
}

