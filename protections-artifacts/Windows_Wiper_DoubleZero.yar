rule Windows_Wiper_DoubleZero_65ec0c50 {
    meta:
        id = "CmWRUH6NHA65c8o8gUCsV"
        fingerprint = "v1_sha256_bce33817d99f71b9d087ea079ef8db08b496315b72cf9d1cf6f0b107a604e52c"
        version = "1.0"
        date = "2022-03-22"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Wiper.DoubleZero"
        reference_sample = "3b2e708eaa4744c76a633391cf2c983f4a098b46436525619e5ea44e105355fe"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "\\Users\\\\.*?\\\\AppData\\\\Roaming\\\\Microsoft.*" wide fullword
        $s2 = "\\Users\\\\.*?\\\\AppData\\\\Local\\\\Application Data.*" wide fullword
        $s3 = "\\Users\\\\.*?\\\\Local Settings.*" wide fullword
        $s4 = "get__beba00adeeb086e6" ascii fullword
        $s5 = "FileShareWrite" ascii fullword
    condition:
        all of them
}

