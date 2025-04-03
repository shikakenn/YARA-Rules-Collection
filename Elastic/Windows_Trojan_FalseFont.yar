rule Windows_Trojan_FalseFont_d1f0d357 {
    meta:
        id = "557seWK7lkdvhMRIpHwZV9"
        fingerprint = "v1_sha256_af356dec77f773cec01626a3823dbea7e9d3719b9d152ec4057c0b97efabf0df"
        version = "1.0"
        date = "2024-03-26"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.FalseFont"
        reference_sample = "364275326bbfc4a3b89233dabdaf3230a3d149ab774678342a40644ad9f8d614"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $s1 = "KillById"
        $s2 = "KillByName"
        $s3 = "SignalRHub"
        $s4 = "ExecUseShell"
        $s5 = "ExecAndKeepAlive"
        $s6 = "SendAllDirectoryWithStartPath"
        $s7 = "AppLiveDirectorySendHard"
        $s8 = "AppLiveDirectorySendScreen"
    condition:
        4 of them
}

