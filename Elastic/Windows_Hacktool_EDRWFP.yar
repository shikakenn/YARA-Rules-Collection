rule Windows_Hacktool_EDRWFP_f6d7db7a {
    meta:
        id = "4SwK5cdWmd7RwWmQgNlljt"
        fingerprint = "v1_sha256_45d427e4f52346b4a18c154bb0afb636c18951fd9c7323846bf2eb7e47928ef6"
        version = "1.0"
        date = "2024-06-10"
        modified = "2024-07-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.EDRWFP"
        reference_sample = "a1fc2f3ded852f75e36e70ae39087e21ae5b6af10e2038d04e61bd500ba511e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "elastic-endpoint.exe"
        $s2 = "elastic-agent.exe"
        $s3 = "MsMpEng.exe"
        $s4 = "FwpmFilterAdd0"
    condition:
        all of them
}

