rule Windows_Ransomware_Cicada3301_99fee259 {
    meta:
        id = "6IR9WnsP3rQxTzas4JKWqV"
        fingerprint = "v1_sha256_18996d70192b0e997eba70c22ed70a2611a7e038a8825308f4d3d002b681939b"
        version = "1.0"
        date = "2024-09-05"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Cicada3301"
        reference_sample = "7b3022437b637c44f42741a92c7f7ed251845fd02dda642c0a47fde179bd984e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "sqldocrtfxlsjpgjpegpnggifwebptiffpsdrawbmppdfdocxdocmdotxdotmodtxlsxxlsmxltxxltmxlsbx"
        $a2 = "keypathhelpsleepno_implno_localno_netno_notesno_iconno_desktop" ascii fullword
        $a3 = "RECOVER--DATA.txt" ascii fullword
        $a4 = "CMD_BCDEDIT_SET_RECOVERY_DISABLED"
        $a5 = "CMD_WMIC_SHADOWCOPY_DELETE"
    condition:
        2 of them
}

