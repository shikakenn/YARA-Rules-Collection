rule Windows_Hacktool_SharpChromium_41ce5080 {
    meta:
        id = "G0eJZYK5bUzHfeVu8gRV6"
        fingerprint = "v1_sha256_50972a6e6af1d7076243320fb6559193e0c46ac1300aa62d12390fdeb2fffdcd"
        version = "1.0"
        date = "2022-11-20"
        modified = "2023-01-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpChromium"
        reference_sample = "9dd65aa53728d51f0f3b9aaf51a24f8a2c3f84b4a4024245575975cf9ad7f2e5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "F1653F20-D47D-4F29-8C55-3C835542AF5F" ascii wide nocase
        $print_str0 = "[X] Exception occurred while writing cookies to file: {0}" ascii wide fullword
        $print_str1 = "[*] All cookies written to {0}" ascii wide fullword
        $print_str2 = "\\{0}-cookies.json" ascii wide fullword
        $print_str3 = "[*] {0} {1} extraction." ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

