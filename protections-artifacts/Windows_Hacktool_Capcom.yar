rule Windows_Hacktool_Capcom_7abae448 {
    meta:
        id = "2Tj0m7tNQ4kuTr1QmXvAvW"
        fingerprint = "v1_sha256_88f25c479cc8970e05ef9d08143afbbbfa17322f34379ba571e3a09105b33ee0"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Subject: CAPCOM Co.,Ltd."
        category = "INFO"
        threat_name = "Windows.Hacktool.Capcom"
        reference_sample = "da6ca1fb539f825ca0f012ed6976baf57ef9c70143b7a1e88b4650bf7a925e24"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 41 50 43 4F 4D 20 43 6F 2E 2C 4C 74 64 2E }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

