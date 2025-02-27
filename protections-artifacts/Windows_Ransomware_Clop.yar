rule Windows_Ransomware_Clop_6a1670aa : beta {
    meta:
        id = "6ljD7V4gFX2euDkhNFG5HT"
        fingerprint = "v1_sha256_afe28000d50495bf2f2adc6cbf0159591ce87bff207f3c6a1d38e09f9ed328d7"
        version = "1.0"
        date = "2020-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies CLOP ransomware in unpacked state"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        threat_name = "Windows.Ransomware.Clop"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $b1 = { FF 15 04 E1 40 00 83 F8 03 74 0A 83 F8 02 }
    condition:
        1 of ($b*)
}

rule Windows_Ransomware_Clop_e04959b5 : beta {
    meta:
        id = "3GAqHlg8quXPwo40JlG2Zu"
        fingerprint = "v1_sha256_039fcb0e48898c7546588cd095fac16f06cf5e5568141aefb6db382a61e80a8d"
        version = "1.0"
        date = "2020-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies CLOP ransomware in unpacked state"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        threat_name = "Windows.Ransomware.Clop"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "-%s\\CIopReadMe.txt" wide fullword
        $a2 = "CIopReadMe.txt" wide fullword
        $a3 = "%s-CIop^_" wide fullword
        $a4 = "%s%s.CIop" wide fullword
        $a5 = "BestChangeT0p^_-666" ascii fullword
        $a6 = ".CIop" wide fullword
        $a7 = "A%s\\ClopReadMe.txt" wide fullword
        $a8 = "%s%s.Clop" wide fullword
        $a9 = "CLOP#666" wide fullword
        $a10 = "MoneyP#666" wide fullword
    condition:
        1 of ($a*)
}

rule Windows_Ransomware_Clop_9ac9ea3e : beta {
    meta:
        id = "6c0YAl5tvcEuE5Lct9xuGu"
        fingerprint = "v1_sha256_1228ee4b934faf1d5f8cf4518974cd2c80a73d84c8a354bde4813fb97ba516d7"
        version = "1.0"
        date = "2020-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies CLOP ransomware in unpacked state"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        threat_name = "Windows.Ransomware.Clop"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $c1 = { 8B 1D D8 E0 40 00 33 F6 8B 3D BC E0 40 00 }
    condition:
        1 of ($c*)
}

rule Windows_Ransomware_Clop_606020e7 : beta {
    meta:
        id = "4ntssjiHLXmk926ijIXRhE"
        fingerprint = "v1_sha256_f5169b324bc19f6f5a04c99f1d3326c97300d038ec383c3eab94eb258963ac30"
        version = "1.0"
        date = "2020-05-03"
        modified = "2021-08-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "Identifies CLOP ransomware in unpacked state"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.clop"
        threat_name = "Windows.Ransomware.Clop"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $d1 = { B8 E1 83 0F 3E F7 E6 8B C6 C1 EA 04 8B CA C1 E1 05 03 CA }
    condition:
        1 of ($d*)
}

