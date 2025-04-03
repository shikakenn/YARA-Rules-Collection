rule Windows_VulnDriver_Speedfan_9b590eee {
    meta:
        id = "74zlZ8MQUxlXBuReIKx5pW"
        fingerprint = "v1_sha256_6f75c0e6b89dd1ceb85c73b7e51fd261ca2804e14a5f8ed6ce3352b3f1bcdfe4"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Subject: Sokno S.R.L."
        category = "INFO"
        threat_name = "Windows.VulnDriver.Speedfan"
        reference_sample = "22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 6F 6B 6E 6F 20 53 2E 52 2E 4C 2E }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

