rule Windows_Hacktool_Seatbelt_674fd535 {
    meta:
        id = "13m2WZzGcVcgDTQgG5sRFd"
        fingerprint = "v1_sha256_1bff820ec5cc9e56e7be4b290a48628115cc1ace5e41278fa76898bf39ef893e"
        version = "1.0"
        date = "2022-10-20"
        modified = "2022-11-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.Seatbelt"
        reference_sample = "a0e467aacd383727d46e766f1c45b424a6d46248118c155c22c538e8773b3ae7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "AEC32155-D589-4150-8FE7-2900DF4554C8" ascii wide nocase
        $str0 = "LogonId=\"(\\d+)" ascii wide
        $str1 = "Domain=\"(.*)\",Name=\"(.*)\"" ascii wide
        $str2 = "^\\W*([a-z]:\\\\.+?(\\.exe|\\.dll|\\.sys))\\W*" ascii wide
        $str3 = "KB\\d+" ascii wide
        $str4 = "(^https?://.+)|(^ftp://)" ascii wide
        $str5 = "[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}" ascii wide
        $str6 = "(http|ftp|https|file)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?" ascii wide
    condition:
        $guid or all of ($str*)
}

