rule Windows_Hacktool_GodPotato_5f1aad81 {
    meta:
        id = "6mb1T7cQveKtskmtKmkuCY"
        fingerprint = "v1_sha256_3028c84a616d47b37b4ef2d41d35ccef5121c06aa042096bca8ea53b528a1eb9"
        version = "1.0"
        date = "2024-06-24"
        modified = "2024-07-02"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.GodPotato"
        reference_sample = "00171bb6e9e4a9b8601e988a8c4ac6f5413e31e1b6d86d24b0b53520cd02184c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "GodPotato" wide fullword
        $a2 = "GodPotatoContext was not initialized" wide fullword
        $a3 = "GodPotatoStorageTrigger" ascii fullword
        $a4 = "[*] DCOM obj GUID: {0}" wide fullword
        $a5 = "[*] DispatchTable: 0x{0:x}" wide fullword
        $a6 = "[*] UseProtseqFunction: 0x{0:x}" wide fullword
        $a7 = "[*] process start with pid {0}" wide fullword
        $a8 = "[!] ImpersonateNamedPipeClient fail error:{0}" wide fullword
        $a9 = "[*] CoGetInstanceFromIStorage: 0x{0:x}" wide fullword
        $a10 = "[*] Trigger RPCS" wide
    condition:
        5 of them
}

