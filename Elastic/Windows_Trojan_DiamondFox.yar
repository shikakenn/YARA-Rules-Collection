rule Windows_Trojan_DiamondFox_18bc11e3 {
    meta:
        id = "4sZzt3iQ02HmVqvGmOL0H4"
        fingerprint = "v1_sha256_c64e4b3349b33cfd0fec1fe41f91ad819bb6b6751e822d7ab8d14638ad27571d"
        version = "1.0"
        date = "2022-03-02"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.DiamondFox"
        reference_sample = "a44c46d4b9cf1254aaabd1e689f84c4d2c3dd213597f827acabface03a1ae6d1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\\wscript.vbs" wide fullword
        $a2 = "\\snapshot.jpg" wide fullword
        $a3 = "&soft=" wide fullword
        $a4 = "ping -n 4 127.0.0.1 > nul" wide fullword
        $a5 = "Select Name from Win32_Process Where Name = '" wide fullword
    condition:
        all of them
}

