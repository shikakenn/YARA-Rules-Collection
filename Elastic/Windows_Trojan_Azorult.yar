rule Windows_Trojan_Azorult_38fce9ea {
    meta:
        id = "2Xt6UvPYxX5Vy6Of7xlKzL"
        fingerprint = "v1_sha256_e23b21992b7ff577d4521c733929638522f4bf57b54c72e5e46196d028d6be26"
        version = "1.0"
        date = "2021-08-05"
        modified = "2021-10-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.Azorult"
        reference_sample = "405d1e6196dc5be1f46a1bd07c655d1d4b36c32f965d9a1b6d4859d3f9b84491"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "/c %WINDIR%\\system32\\timeout.exe 3 & del \"" wide fullword
        $a2 = "%APPDATA%\\.purple\\accounts.xml" wide fullword
        $a3 = "%TEMP%\\curbuf.dat" wide fullword
        $a4 = "PasswordsList.txt" ascii fullword
        $a5 = "Software\\Valve\\Steam" wide fullword
    condition:
        all of them
}

