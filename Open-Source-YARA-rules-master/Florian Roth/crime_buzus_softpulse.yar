
rule Win32_Buzus_Softpulse {
    meta:
        id = "5pAAbFnrkxbij1JK0h9MSm"
        fingerprint = "v1_sha256_da476c2fb3edc7dc24b5739416b87ccf4ec6cf33911e26ef8e8fbb01f35130cc"
        version = "1.0"
        score = 75
        date = "2015-05-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Trojan Buzus / Softpulse"
        category = "INFO"
        hash = "2f6df200e63a86768471399a74180466d2e99ea9"

    strings:
        $x1 = "pi4izd6vp0.com" fullword ascii

        $s1 = "SELECT * FROM Win32_Process" fullword wide
        $s4 = "CurrentVersion\\Uninstall\\avast" fullword wide
        $s5 = "Find_RepeatProcess" fullword ascii
        $s6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\" fullword wide
        $s7 = "myapp.exe" fullword ascii
        $s14 = "/c ping -n 1 www.google" wide
    condition:
        uint16(0) == 0x5a4d and 
            ( 
                ( $x1 and 2 of ($s*) ) or
                all of ($s*) 
            )
}
