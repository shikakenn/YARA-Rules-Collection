rule Windows_VulnDriver_VBox_3315863f {
    meta:
        id = "1EZd9beIZc9dXWwFuAp73t"
        fingerprint = "v1_sha256_ba4e6a94516e36dcd6140b6732d959703e2c58a79add705b9260001ea26db738"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Subject: innotek GmbH"
        category = "INFO"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "42d926cfb3794f9b1e3cb397498696cb687f505e15feb9df11b419c49c9af498"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $subject_name = { 06 03 55 04 03 [2] 69 6E 6E 6F 74 65 6B 20 47 6D 62 48 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name
}

rule Windows_VulnDriver_VBox_1b1c5cd5 {
    meta:
        id = "7hBRWG5o7jZV6KoEQoFIfY"
        fingerprint = "v1_sha256_5fcfffea021aee8d18172383df0e65f8c618fab545c800f1a7b659e8112c6c0f"
        version = "1.0"
        date = "2022-04-07"
        modified = "2022-04-07"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "Name: VBoxDrv.sys, Version: 3.0.0.0"
        category = "INFO"
        threat_name = "Windows.VulnDriver.VBox"
        reference_sample = "1684e24dae20ab83ab5462aa1ff6473110ec53f52a32cfb8c1fe95a2642c6d22"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 42 00 6F 00 78 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x00][\x00-\x00])([\x00-\x03][\x00-\x00])([\x00-\x00][\x00-\x00])([\x00-\x00][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x02][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff]))/
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version
}

