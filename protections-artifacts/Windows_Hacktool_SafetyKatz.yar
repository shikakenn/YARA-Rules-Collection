rule Windows_Hacktool_SafetyKatz_072b7370 {
    meta:
        id = "B8qjqU3PrduHKLM0Z5hry"
        fingerprint = "v1_sha256_cedd3ede487371a8e0d29804f2b81ae808c7ad01bd803fa39dc2c50e472cff43"
        version = "1.0"
        date = "2022-11-20"
        modified = "2023-01-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SafetyKatz"
        reference_sample = "89a456943cf6d2b3cd9cdc44f13a23640575435ed49fa754f7ed358c1a3b6ba9"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "8347E81B-89FC-42A9-B22C-F59A6A572DEC" ascii wide nocase
        $print_str0 = "[X] Not in high integrity, unable to grab a handle to lsass!" ascii wide fullword
        $print_str1 = "[X] Dump directory \"{0}\" doesn't exist!" ascii wide fullword
        $print_str2 = "[X] Process is not 64-bit, this version of Mimikatz won't work yo'!" ascii wide fullword
        $print_str3 = "[+] Dump successful!" ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

