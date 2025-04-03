rule Windows_Trojan_MetaStealer_f94e2464 {
    meta:
        id = "4cM3PVymG3HSlid1Gy3q3M"
        fingerprint = "v1_sha256_bf374bda2ca7c7bcec1ff092bbc9c3fd95c33faa78a6ea105a7b12b8e80a2e23"
        version = "1.0"
        date = "2024-03-27"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.MetaStealer"
        reference_sample = "14ca15c0751207103c38f1a2f8fdc73e5dd3d58772f6e5641e54e0c790ecd132"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $string1 = "AvailableLanguages" fullword
        $string2 = "GetGraphicCards" fullword
        $string3 = "GetVs" fullword
        $string4 = "GetSerialNumber" fullword
        $string5 = "net.tcp://" wide
        $string6 = "AntivirusProduct|AntiSpyWareProduct|FirewallProduct" wide
        $string7 = "wallet.dat" wide
        $string8 = "[A-Za-z\\d]{24}\\.[\\w-]{6}\\.[\\w-]{27}" wide
        $string9 = "Software\\Valve\\Steam" wide
        $string10 = "{0}\\FileZilla\\recentservers.xml" wide
        $string11 = "{0}\\FileZilla\\sitemanager.xml" wide
        $string12 = "([a-zA-Z0-9]{1000,1500})" wide
        $string13 = "\\qemu-ga.exe" wide
        $string14 = "metaData" wide
        $string15 = "%DSK_23%" wide
        $string16 = "CollectMemory" fullword
    condition:
        all of them
}

rule Windows_Trojan_MetaStealer_a07e395c {
    meta:
        id = "5EcoyWLJsInki27BJ7ScOz"
        fingerprint = "v1_sha256_2464cf1dc5747c93598354329371ea6111c3cbf34a6db83076c9465b867a0e47"
        version = "1.0"
        date = "2024-10-23"
        modified = "2024-10-29"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.MetaStealer"
        reference_sample = "973a9056040af402d6f92f436a287ea164fae09c263f80aba0b8d5366ed9957a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $b = "SeImpersonatePrivilege" wide fullword
        $d = { 34 36 33 41 42 45 43 46 2D 34 31 30 44 2D 34 30 37 46 2D 38 41 46 35 2D 30 44 46 33 35 41 30 30 35 43 43 38 }
        $e = { 25 1F 0F 5F 0C 1A 63 1F 0F 5F 0D 09 1F 09 }
    condition:
        all of them
}

