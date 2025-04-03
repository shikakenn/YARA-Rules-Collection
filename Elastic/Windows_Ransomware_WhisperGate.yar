rule Windows_Ransomware_WhisperGate_c80f3b4b {
    meta:
        id = "4pZ7RMM0FcWRWWuBCDYFif"
        fingerprint = "v1_sha256_04452141a867d4f6fce618c21795cc142a1265b56c62ecb9e579003d36b4b2b9"
        version = "1.0"
        date = "2022-01-17"
        modified = "2022-01-17"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.WhisperGate"
        reference_sample = "a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $buffer = { E8 ?? ?? ?? ?? BE 20 40 40 00 29 C4 8D BD E8 DF FF FF E8 ?? ?? ?? ?? B9 00 08 00 00 F3 A5 }
        $note = { 59 6F 75 72 20 68 61 72 64 20 64 72 69 76 65 20 68 61 73 20 62 65 65 6E 20 63 6F 72 72 75 70 74 65 64 2E 0D 0A }
    condition:
        all of them
}

rule Windows_Ransomware_WhisperGate_3476008e {
    meta:
        id = "PRSzc1aapbvtsDBtJxSxV"
        fingerprint = "v1_sha256_729818df1b6b82fc00eba0fe1c9139ec4746e1775146ab7fdea9e25dec1cddea"
        version = "1.0"
        date = "2022-01-18"
        modified = "2022-01-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.WhisperGate"
        reference_sample = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "cmd.exe /min /C ping 111.111.111.111 -n 5 -w 10 > Nul & Del /f /q \"%s\"" ascii fullword
        $a2 = "%.*s.%x" wide fullword
        $a3 = "A:\\Windows" wide fullword
        $a4 = ".ONETOC2" wide fullword
    condition:
        all of them
}

