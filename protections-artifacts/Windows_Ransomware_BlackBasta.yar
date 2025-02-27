rule Windows_Ransomware_BlackBasta_494d3c54 {
    meta:
        id = "7VUVaGrNp49c8de4P88m4d"
        fingerprint = "v1_sha256_1ecb3c95a2d3f91d267f0b625fffc8477612fde9de3942eff8eb13115c0af6b8"
        version = "1.0"
        date = "2022-08-06"
        modified = "2022-08-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.BlackBasta"
        reference_sample = "357fe8c56e246ffacd54d12f4deb9f1adb25cb772b5cd2436246da3f2d01c222"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Done time: %.4f seconds, encrypted: %.4f gb" ascii fullword
        $a2 = "Creating readme at %s" wide fullword
        $a3 = "All of your files are currently encrypted by no_name_software." ascii fullword
        $a4 = "DON'T move or rename your files. These parameters can be used for encryption/decryption process." ascii fullword
        $b1 = "Your data are stolen and encrypted" ascii fullword
        $b2 = "bcdedit /deletevalue safeboot" ascii fullword
        $b3 = "Your company id for log in:"
        $byte_seq = { 0F AF 45 DC 8B CB 0F AF 4D DC 0F AF 5D D8 0F AF 55 D8 8B F9 }
        $byte_seq2 = { 18 FF 24 1E 18 FF 64 61 5D FF CF CF CF FF D0 D0 D0 FF D0 D0 D0 FF }
    condition:
        4 of them
}

