/*
    Yara Rule Set
    Author: Kudelski Security (modified by Florian Roth)
    Reference: https://www.kudelskisecurity.com/sites/default/files/sphinx_moth_cfc_report.pdf
    Date: 2015-11-23
    Identifier: Sphinx Moth
*/

rule Sphinx_Moth_cudacrt { 
    meta:
        id = "53qxPmOQR79TmoE3C6ZMoJ"
        fingerprint = "v1_sha256_ae7ff3d5ffd29de80ce5dcccde9af04d2537a279fe35f6e94257d59a462ba6a0"
        version = "1.0"
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kudelski Security - Nagravision SA"
        description = "sphinx moth threat group file cudacrt.dll"
        category = "INFO"
        reference = "www.kudelskisecurity.com"

    strings:
        $s0 = "HPSSOEx.dll" fullword wide
        $s1 = "255.255.255.254" fullword wide
        $s2 = "SOFTWARE\\SsoAuth\\Service" fullword wide

        $op0 = { ff 15 5f de 00 00 48 8b f8 48 85 c0 75 0d 48 8b } /* Opcode */ 
        $op1 = { 45 33 c9 4c 8d 05 a7 07 00 00 33 d2 33 c9 ff 15 } /* Opcode */ 
        $op2 = { e8 7a 1c 00 00 83 f8 01 74 17 b9 03 } /* Opcode */
    condition:
        uint16(0) == 0x5a4d and filesize < 243KB and all of ($s*) and 1 of ($op*)
}

rule Sphinx_Moth_h2t { 
    meta:
        id = "5NqO5TJU4yFgsYuOaiYQSY"
        fingerprint = "v1_sha256_7aca260d415de84cf432b18385db6a9768a036e3bd0a9aa8ded4a1bfcad26d0c"
        version = "1.0"
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kudelski Security - Nagravision SA (modified by Florian Roth)"
        description = "sphinx moth threat group file h2t.dat"
        category = "INFO"
        reference = "www.kudelskisecurity.com"

    strings:
        $x1 = "%s <proxy ip> <proxy port> <target ip> <target port> <cmd> [arg1 cmd] ... [argX cmd]" fullword ascii 
        
        $s1 = "[-] Error in connection() %d - %s" fullword ascii
        $s2 = "[-] Child process exit." fullword ascii
        $s3 = "POST http://%s:%s/ HTTP/1.1" fullword ascii
        $s4 = "pipe() to" fullword ascii
        $s5 = "pipe() from" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 156KB and ($x1 or all of ($s*))
}

rule Sphinx_Moth_iastor32 { 
    meta:
        id = "5nkWdOkQgMlBQvSOshH3lu"
        fingerprint = "v1_sha256_056949677654a88fb430c988939006dacfefdabbe12824936a01e5aabbb73441"
        version = "1.0"
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kudelski Security - Nagravision SA"
        description = "sphinx moth threat group file iastor32.exe"
        category = "INFO"
        reference = "www.kudelskisecurity.com"

    strings:
        $s0 = "MIIEpQIBAAKCAQEA4lSvv/W1Mkz38Q3z+EzJBZRANzKrlxeE6/UXWL67YtokF2nN" fullword ascii /* private key */
        $s1 = "iAeS3CCA4wli6+9CIgX8SAiXd5OezHvI1jza61z/flsqcC1IP//gJVt16nRx3s9z" fullword ascii /* private key */
    condition:
        uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule Sphinx_Moth_kerberos32 {
    meta:
        id = "5Kj0RmxbU3J01eVURNVxEE"
        fingerprint = "v1_sha256_5b672c9b9b0ffffd8f243832ea217bfc10b08026c71d297ee1047ca999fb829c"
        version = "1.0"
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kudelski Security - Nagravision SA (modified by Florian Roth)"
        description = "sphinx moth threat group file kerberos32.dll"
        category = "INFO"
        reference = "www.kudelskisecurity.com"

    strings:
        $x1 = "%WINDIR%\\ativpsrz.bin" fullword ascii
        $x2 = "%WINDIR%\\ativpsrn.bin" fullword ascii
        $x3 = "kerberos32.dll" fullword wide
        $x4 = "KERBEROS64.dll" fullword ascii
        $x5 = "kerberos%d.dll" fullword ascii

        $s1 = "\\\\.\\pipe\\lsassp" fullword ascii
        $s2 = "LSASS secure pipe" fullword ascii /* PEStudio Blacklist: strings */ 
        $s3 = "NullSessionPipes" fullword ascii /* PEStudio Blacklist: strings */ 
        $s4 = "getlog" fullword ascii
        $s5 = "startlog" fullword ascii /* PEStudio Blacklist: strings */
        $s6 = "stoplog" fullword ascii /* PEStudio Blacklist: strings */
        $s7 = "Unsupported OS (%d)" fullword ascii /* PEStudio Blacklist: strings */ 
        $s8 = "Unsupported OS (%s)" fullword ascii /* PEStudio Blacklist: strings */
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and (2 of ($x*) or all of ($s*))
}

rule Sphinx_Moth_kerberos64 { 
    meta:
        id = "6RRO9SSGpaUhtPlOeRi8WO"
        fingerprint = "v1_sha256_13aeb72fcd0f5fd6e73464a90787c756c50569f9eae48945e4ff90d8f9073585"
        version = "1.0"
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kudelski Security - Nagravision SA (modified by Florian Roth)"
        description = "sphinx moth threat group file kerberos64.dll"
        category = "INFO"
        reference = "www.kudelskisecurity.com"

    strings:
        $s0 = "KERBEROS64.dll" fullword ascii
        $s1 = "zeSecurityDescriptor" fullword ascii
        $s2 = "SpGetInfo" fullword ascii
        $s3 = "SpShutdown" fullword ascii
        $op0 = { 75 05 e8 6a c7 ff ff 48 8b 1d 47 d6 00 00 33 ff } /* Opcode */ 
        $op1 = { 48 89 05 0c 2b 01 00 c7 05 e2 29 01 00 09 04 00 } /* Opcode */ 
        $op2 = { 48 8d 3d e3 ee 00 00 ba 58 } /* Opcode */
    condition:
        uint16(0) == 0x5a4d and filesize < 406KB and all of ($s*) and 1 of ($op*)
}

rule Sphinx_Moth_nvcplex { 
    meta:
        id = "5iNrooARljjgCafJvzQNWx"
        fingerprint = "v1_sha256_2f851c0ab8c4a426b00addfbe0da7ceebb08e93014efcb11d64247d14fec909b"
        version = "1.0"
        date = "2015-08-06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Kudelski Security - Nagravision SA"
        description = "sphinx moth threat group file nvcplex.dat"
        category = "INFO"
        reference = "www.kudelskisecurity.com"

    strings:
        $s0 = "mshtaex.exe" fullword wide
        $op0 = { 41 8b cc 44 89 6c 24 28 48 89 7c 24 20 ff 15 d3 } /* Opcode */ 
        $op1 = { 48 3b 0d ad 8f 00 00 74 05 e8 ba f5 ff ff 48 8b } /* Opcode */ 
        $op2 = { 8b ce e8 49 47 00 00 90 8b 43 04 89 05 93 f1 00 } /* Opcode */
    condition:
        uint16(0) == 0x5a4d and filesize < 214KB and all of them
}
