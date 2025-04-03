rule Careto {
    meta:
        id = "7lO2NAzyylKbd4c0aEeaLw"
        fingerprint = "v1_sha256_f56725be99dc746998d24448245329892144a8932342a696f3a692364044e419"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto generic malware signature"
        category = "INFO"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

    strings:

        /* General */
        $name1 = "Careto" ascii wide
        $s_1 = "GetSystemReport" ascii wide
        $s_2 = "SystemReport.txt" ascii wide
        $s_3 = /URL_AUX\w*=/ ascii wide
        $s_4 = /CaretoPruebas.+release/

        /* Certificate */
        $sign_0 = "Sofia"
        $sign_1 = "TecSystem Ltd"
        $sign_2 = "<<<Obsolete>>>" wide

        /* Encryption keys */
        $rc4_1 = "!$7be&.Kaw-12[}" ascii wide
        $rc4_2 = "Caguen1aMar" ascii wide
        /* http://laboratorio.blogs.hispasec.com/2014/02/analisis-del-algoritmo-de-descifrado.html */
        $rc4_3 = {8d 85 86 8a 8f 80 88 83 8d 82 88 85 86 8f 8f 87 8d 82 83 82 8c 8e 83 8d 89 82 86 87 82 83 83 81}

        /* Decryption routine fragment */
        $dec_1 = {8b 4d 08 0f be 04 59 0f be 4c 59 01 2b c7 c1 e0 04 2b cf 0b c1 50 8d 85 f0 fe ff ff}
        $dec_2 = {8b 4d f8 8b 16 88 04 11 8b 06 41 89 4d f8 c6 04 01 00 43 3b 5d fc}

    condition:
        $name1 and (any of ($s_*)) or all of ($sign_*) or any of ($rc4_*) or all of ($dec_*)
}

rule Careto_SGH {
    meta:
        id = "1SUqo14sUpq70PuKgvGtgp"
        fingerprint = "v1_sha256_713da3fa106d66369a6785168f6bf078b7e9475a941ddf66879e5e2b4cebe032"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto SGH component signature"
        category = "INFO"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

    strings:
        $m1 = "PGPsdkDriver" ascii wide fullword
        $m2 = "jpeg1x32" ascii wide fullword
        $m3 = "SkypeIE6Plugin" ascii wide fullword
        $m4 = "CDllUninstall" ascii wide fullword
    condition:
        2 of them
}

rule Careto_OSX_SBD {
    meta:
        id = "6RVNwkP8e95kfFT2qpAXel"
        fingerprint = "v1_sha256_66cc7a19d5a81ba0f578bb9363edfce97b592c800737ab016e3a4f5459bed107"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto OSX component signature"
        category = "INFO"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

    strings:
        /* XORed "/dev/null strdup() setuid(geteuid())" */
        $1 = {FF 16 64 0A 7E 1A 63 4D 21 4D 3E 1E 60 0F 7C 1A 65 0F 74 0B 3E 1C 7F 12}
    condition:
        all of them
}

rule Careto_CnC {
    meta:
        id = "6LSUODpyaGDrht8qNSWZwm"
        fingerprint = "v1_sha256_db92ef2593b9ddec43f89d5264c862bae9200ad57c260f0e807adabfe2e3df9e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto CnC communication signature"
        category = "INFO"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

    strings:
        $1 = "cgi-bin/commcgi.cgi" ascii wide
        $2 = "Group" ascii wide
        $3 = "Install" ascii wide
        $4 = "Bn" ascii wide
    condition:
        all of them
}

rule Careto_CnC_domains {
    meta:
        id = "4cjsaJsJEJQeR6ryvgP6ik"
        fingerprint = "v1_sha256_5164b91e6df8d40984d1b035fce58a0f2b9666d588427452dbd032f508fcc9ff"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault (Alberto Ortega)"
        description = "TheMask / Careto known command and control domains"
        category = "INFO"
        reference = "www.securelist.com/en/downloads/vlpdfs/unveilingthemask_v1.0.pdf"

    strings:
        $1 = "linkconf.net" ascii wide nocase
        $2 = "redirserver.net" ascii wide nocase
        $3 = "swupdt.com" ascii wide nocase
    condition:
        any of them
}
