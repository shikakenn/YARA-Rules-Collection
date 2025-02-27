rule Windows_Trojan_BITSloth_05fc3a0a {
    meta:
        id = "6VfxaiCdRIHMAoykTpCbqZ"
        fingerprint = "v1_sha256_8210dc28cf408f7f836aad3c32868ea21dd0862070c2c37d98b089a80be9285e"
        version = "1.0"
        date = "2024-07-16"
        modified = "2024-07-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.BITSloth"
        reference_sample = "0944b17a4330e1c97600f62717d6bae7e4a4260604043f2390a14c8d76ef1507"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str_1 = "/%s/index.htm?RspID=%d" wide fullword
        $str_2 = "/%s/%08x.rpl" wide fullword
        $str_3 = "/%s/wu.htm" wide fullword
        $str_4 = "GET_DESKDOP" wide fullword
        $str_5 = "http://updater.microsoft.com/index.aspx" wide fullword
        $str_6 = "[U] update error..." wide fullword
        $str_7 = "RMC_KERNEL ..." wide fullword
        $seq_global_protocol_check = { 81 3D ?? ?? ?? ?? F9 03 00 00 B9 AC 0F 00 00 0F 46 C1 }
        $seq_exit_windows = { 59 85 C0 0F 84 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A 02 EB ?? 56 EB }
    condition:
        2 of them
}

