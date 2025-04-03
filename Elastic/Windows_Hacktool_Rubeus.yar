rule Windows_Hacktool_Rubeus_43f18623 {
    meta:
        id = "3ZPr4bDYmX7SbEGNp8u37g"
        fingerprint = "v1_sha256_8714f30e12c0dc61c83491a71dbf9f1e9b6bc66663a8f2c069e7a7841d52cf68"
        version = "1.0"
        date = "2022-10-20"
        modified = "2022-11-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.Rubeus"
        reference_sample = "b7b4691ad1cdad7663c32d07e911a03d9cc8b104f724c2825fd4957007649235"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "658C8B7F-3664-4A95-9572-A3E5871DFC06" ascii wide nocase
        $print_str0 = "[*] Printing argument list for use with Rubeus" ascii wide
        $print_str1 = "[+] Ticket successfully imported!" ascii wide
        $print_str2 = "[+] Tickets successfully purged!" ascii wide
        $print_str3 = "[*] Searching for accounts that support AES128_CTS_HMAC_SHA1_96/AES256_CTS_HMAC_SHA1_96" ascii wide
        $print_str4 = "[*] Action: TGT Harvesting (with auto-renewal)" ascii wide
        $print_str5 = "[X] Unable to retrieve TGT using tgtdeleg" ascii wide
        $print_str6 = "[!] Unhandled Rubeus exception:" ascii wide
        $print_str7 = "[*] Using a TGT /ticket to request service tickets" ascii wide
    condition:
        $guid or 4 of ($print_str*)
}

