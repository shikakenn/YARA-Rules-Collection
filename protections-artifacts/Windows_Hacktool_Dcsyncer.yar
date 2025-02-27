rule Windows_Hacktool_Dcsyncer_425579c5 {
    meta:
        id = "iC8tbgSHmuQM6GaEsnE3w"
        fingerprint = "v1_sha256_b0330adf1d4420ddf1f302974d2e4179f52ab1c8dc2f294ddf52286d714e0463"
        version = "1.0"
        date = "2021-09-15"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "MGIxY2/05+FBDTur++++0OUs"
        category = "INFO"
        threat_name = "Windows.Hacktool.Dcsyncer"
        reference_sample = "af7dbc84efeb186006d75d095f54a266f59e6b2348d0c20591da16ae7b7d509a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "[x] dcsync: Error in ProcessGetNCChangesReply" wide fullword
        $a2 = "[x] getDCBind: RPC Exception 0x%08x (%u)" wide fullword
        $a3 = "[x] getDomainAndUserInfos: DomainControllerInfo: 0x%08x (%u)" wide fullword
        $a4 = "[x] ProcessGetNCChangesReply_decrypt: Checksums don't match (C:0x%08x - R:0x%08x)" wide fullword
    condition:
        any of them
}

