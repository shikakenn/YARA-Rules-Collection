rule Windows_Hacktool_SharpShares_88cdcd52 {
    meta:
        id = "1nQ4xyJCujmLt05KhJJeKz"
        fingerprint = "v1_sha256_85c59b939da6158f931e779c2884cea77b80fab54ee5e157d86afa19f0253db3"
        version = "1.0"
        date = "2022-10-20"
        modified = "2022-11-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpShares"
        reference_sample = "bbdd3620a67aedec4b9a68b2c9cc880b6631215e129816aea19902a6f4bc6f41"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "BCBC884D-2D47-4138-B68F-7D425C9291F9" ascii wide nocase
        $print_str0 = "all enabled computers with \"primary\" group \"Domain Computers\"" ascii wide
        $print_str1 = "all enabled Domain Controllers (not read-only DCs)" ascii wide
        $print_str2 = "all enabled servers excluding Domain Controllers or read-only DCs" ascii wide
        $str0 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" ascii wide
        $str1 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(userAccountControl:1.2.840.113556.1.4.803:=8192))" ascii wide
        $str2 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))" ascii wide
        $str3 = "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(!(userAccountControl:1.2.840.113556.1.4.803:=67100867)))" ascii wide
        $str4 = "servers-exclude-dc" ascii wide
        $str5 = "all enabled servers" ascii wide
        $str6 = "[w] \\\\{0}\\{1}" ascii wide
        $str7 = "[-] \\\\{0}\\{1}" ascii wide
    condition:
        $guid or all of ($print_str*) or 4 of ($str*)
}

