rule Windows_Ransomware_Hellokitty_8859e8e8 {
    meta:
        id = "1QhfQnBTkzi6FdUhjAycBi"
        fingerprint = "v1_sha256_72cc718724d9d9a391a9f7a0932ebf397c2ab79558437533bef6e380b06baff9"
        version = "1.0"
        date = "2021-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Hellokitty"
        reference_sample = "3ae7bedf236d4e53a33f3a3e1e80eae2d93e91b1988da2f7fcb8fde5dcc3a0e9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "HelloKittyMutex" wide fullword
        $a2 = "%s\\read_me_lkd.txt" wide fullword
        $a3 = "Win32_ShadowCopy.ID='%s'" wide fullword
        $a4 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!" wide fullword
        $a5 = "%s/secret/%S" wide fullword
        $a6 = "DECRYPT_NOTE.txt" wide fullword
        $a7 = "Some data has been stored in our servers and ready for publish." wide fullword
        $a9 = "To contact with us you have ONE week from the encryption time, after decryption keys and your personal contact link will be dele" wide
        $a10 = "In case of your disregard, we reserve the right to dispose of the dumped data at our discretion including publishing." wide fullword
        $a11 = "IMPORTANT: Don't modify encrypted files or you can damage them and decryption will be impossible!" wide fullword
        $b1 = "/f /im \"%s\"" wide fullword
        $b2 = "stop \"%s\"" wide fullword
        $b3 = "/f /im %s" wide fullword
        $b4 = "stop %s" wide fullword
    condition:
        (2 of ($a*) and 2 of ($b*)) or (5 of ($a*))
}

rule Windows_Ransomware_Hellokitty_4b668121 {
    meta:
        id = "2dgTx4l4189lg6Wtxp7B3f"
        fingerprint = "v1_sha256_00c7a492c304f12b9909e35cf069618a1103311a69e3e8951ca196c3c663b12a"
        version = "1.0"
        date = "2021-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Hellokitty"
        reference_sample = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "(%d) [%d] %s: STOP DOUBLE PROCESS RUN" ascii fullword
        $a2 = "(%d) [%d] %s: Looking for folder from cmd: %S" ascii fullword
        $a3 = "(%d) [%d] %s: ERROR: Failed to encrypt AES block" ascii fullword
        $a4 = "gHelloKittyMutex" wide fullword
        $a5 = "/C ping 127.0.0.1 & del %s" wide fullword
        $a6 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!"
        $a7 = "read_me_lkdtt.txt" wide fullword
        $a8 = "If you want to get it, you must pay us some money and we will help you." wide fullword
    condition:
        5 of them
}

rule Windows_Ransomware_Hellokitty_d9391a1a {
    meta:
        id = "JVZzacudMO381FSNdJVOX"
        fingerprint = "v1_sha256_074ca47c0526d9828f3c07c7d6dbdd1cec609670d70340b022ae2c712ad80305"
        version = "1.0"
        date = "2021-05-03"
        modified = "2023-01-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Hellokitty"
        reference_sample = "10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 83 C4 04 85 DB 75 12 0F 10 45 D4 83 C7 10 0F 11 06 83 C6 10 83 }
        $a2 = { 89 45 F8 3B 5D F4 75 25 3B C6 75 21 6A FF FF 75 14 8B D1 83 }
    condition:
        any of them
}

