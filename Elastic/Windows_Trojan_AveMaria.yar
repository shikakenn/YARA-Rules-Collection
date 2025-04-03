rule Windows_Trojan_AveMaria_31d2bce9 {
    meta:
        id = "4l6EqUIIPbRSewsi6CiELU"
        fingerprint = "v1_sha256_7ba59c3be07e35b415719b60b14a0f629619e5729c20f50f00dbea0c2f8bd026"
        version = "1.0"
        date = "2021-05-30"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.AveMaria"
        reference_sample = "5767bca39fa46d32a6cb69ef7bd1feaac949874768dac192dbf1cf43336b3d7b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " ascii fullword
        $a2 = "SMTP Password" wide fullword
        $a3 = "select signon_realm, origin_url, username_value, password_value from logins" ascii fullword
        $a4 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide fullword
        $a5 = "for /F \"usebackq tokens=*\" %%A in (\"" wide fullword
        $a6 = "\\Torch\\User Data\\Default\\Login Data" wide fullword
        $a7 = "/n:%temp%\\ellocnak.xml" wide fullword
        $a8 = "\"os_crypt\":{\"encrypted_key\":\"" wide fullword
        $a9 = "Hey I'm Admin" wide fullword
        $a10 = "\\logins.json" wide fullword
        $a11 = "Accounts\\Account.rec0" ascii fullword
        $a12 = "warzone160" ascii fullword
        $a13 = "Ave_Maria Stealer OpenSource github Link: https://github.com/syohex/java-simple-mine-sweeper" wide fullword
    condition:
        8 of ($a*)
}

