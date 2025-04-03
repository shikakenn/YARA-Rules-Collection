rule Windows_Trojan_P8Loader_e478a831 {
    meta:
        id = "V0qBc95plq2mKMFwV96CQ"
        fingerprint = "v1_sha256_f1a7de6bb4477ea82c18aea1ddc4481de2fc362ce5321f4205bb3b74c1c45a7e"
        version = "1.0"
        date = "2023-04-13"
        modified = "2023-05-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/elastic-charms-spectralviper"
        threat_name = "Windows.Trojan.P8Loader"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\t[+] Create pipe direct std success\n" fullword
        $a2 = "\tPEAddress: %p\n" fullword
        $a3 = "\tPESize: %ld\n" fullword
        $a4 = "DynamicLoad(%s, %s) %d\n" fullword
        $a5 = "LoadLibraryA(%s) FAILED in %s function, line %d" fullword
        $a6 = "\t[+] No PE loaded on memory\n" wide fullword
        $a7 = "\t[+] PE argument: %ws\n" wide fullword
        $a8 = "LoadLibraryA(%s) FAILED in %s function, line %d" fullword
    condition:
        5 of them
}

