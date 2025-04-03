rule Linux_Cryptominer_Miancha_646803ef {
    meta:
        id = "5gwPbSvRjcaom1BfwFicGr"
        fingerprint = "v1_sha256_8fd386c0e7037565e8ab206642cc8c11f05ca727b365b94ffdd991f4bed95556"
        version = "1.0"
        date = "2021-01-12"
        modified = "2021-09-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Cryptominer.Miancha"
        reference_sample = "4c7761c9376ed065887dc6ce852491641419eb2d1f393c37ed0a5cb29bd108d4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $a = { 6F DC 66 0F 73 FB 04 66 0F EF C1 66 0F 6F D3 66 0F EF C7 66 0F 6F }
    condition:
        all of them
}

