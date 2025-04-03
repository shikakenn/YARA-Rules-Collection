rule Multi_Hacktool_Stowaway_89f1d452 {
    meta:
        id = "4N9DHD5Pge0qnGtOLlNsG1"
        fingerprint = "v1_sha256_c5db1335fea606ec32f7a6540ee4dee637dd2ad5aee27e092b89fa03ad085690"
        version = "1.0"
        date = "2024-06-28"
        modified = "2024-07-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Multi.Hacktool.Stowaway"
        reference_sample = "c073d3be469c8eea0f007bb37c722bad30e06dc994d3a59773838ed8be154c95"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"

    strings:
        $a1 = "Stowaway/share.ActivePreAuth" ascii fullword
        $a2 = "Stowaway/agent/handler" ascii fullword
        $a3 = "Origin: http://stowaway:22" ascii fullword
        $a4 = "Stowaway/admin.NewAdmin" ascii fullword
        $a5 = "Stowaway/global/global.go" ascii fullword
        $a6 = "Stowaway/crypto.AESDecrypt" ascii fullword
        $a7 = "Stowaway/utils.CheckIfIP4" ascii fullword
        $a8 = "Exit Stowaway"
        $a9 = "Stowaway/protocol.ConstructMessage" ascii fullword
    condition:
        3 of them
}

