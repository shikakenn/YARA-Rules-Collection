rule Windows_Hacktool_SharpDump_7c17d8b1 {
    meta:
        id = "23657VGPvHBpwqUfoIyXmm"
        fingerprint = "v1_sha256_10ca29b097d9f1cef27349751e8f1e584ead1056a636224a80f00823ca878c13"
        version = "1.0"
        date = "2022-10-20"
        modified = "2022-11-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpDump"
        reference_sample = "14c3ea569a1bd9ac3aced4f8dd58314532dbf974bfa359979e6c7b6a4bbf41ca"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "9c9bba3-a0ea-431c-866c-77004802d" ascii wide nocase
        $print_str0 = "Please use \"SharpDump.exe [pid]\" format" ascii wide
        $print_str1 = "[*] Use \"sekurlsa::minidump debug.out\" \"sekurlsa::logonPasswords full\" on the same OS/arch" ascii wide
        $print_str2 = "[+] Dumping completed. Rename file to \"debug{0}.gz\" to decompress" ascii wide
        $print_str3 = "[X] Not in high integrity, unable to MiniDump!" ascii wide
    condition:
        $guid or all of ($print_str*)
}

