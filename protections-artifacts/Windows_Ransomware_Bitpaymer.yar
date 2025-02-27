rule Windows_Ransomware_Bitpaymer_d74273b3 : beta {
    meta:
        id = "5Hb4UBrC8w3DPTVJLo6H1G"
        fingerprint = "v1_sha256_126246689b28e92ed10bfa6165f06ff7d4f0e062de7c58b821eaaf5e3cae9306"
        version = "1.0"
        date = "2020-06-25"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies BITPAYMER ransomware"
        category = "INFO"
        reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
        threat_name = "Windows.Ransomware.Bitpaymer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $b1 = { 24 E8 00 00 00 29 F0 19 F9 89 8C 24 88 00 00 00 89 84 24 84 00 }
    condition:
        1 of ($b*)
}

rule Windows_Ransomware_Bitpaymer_bca25ac6 : beta {
    meta:
        id = "5XJwPgxpkHafN1mVSbIKZd"
        fingerprint = "v1_sha256_7670f9dafacc8fc5998c1974af66ede388c0997545da067648fec4fd053f0001"
        version = "1.0"
        date = "2020-06-25"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies BITPAYMER ransomware"
        category = "INFO"
        reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
        threat_name = "Windows.Ransomware.Bitpaymer"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "RWKGGE.PDB" fullword
        $a2 = "*Qf69@+mESRA.RY7*+6XEF#NH.pdb" fullword
        $a3 = "04QuURX.pdb" fullword
        $a4 = "9nuhuNN.PDB" fullword
        $a5 = "mHtXGC.PDB" fullword
        $a6 = "S:\\Work\\_bin\\Release-Win32\\wp_encrypt_new.pdb" fullword
        $a7 = "C:\\Work\\_bin\\Release-Win32\\wp_encrypt.pdb" fullword
        $a8 = "k:\\softcare\\release\\h2O.pdb" fullword
    condition:
        1 of ($a*)
}

