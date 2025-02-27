rule Windows_Hacktool_ExecuteAssembly_f41f4df6 {
    meta:
        id = "aXMD68zSSD3mUNDapDkvJ"
        fingerprint = "v1_sha256_ab72dec636a96338e16fd57f2db4bb52e38fe61315b42c2ffe9c4566fc0326d3"
        version = "1.0"
        date = "2023-03-28"
        modified = "2023-04-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.ExecuteAssembly"
        reference_sample = "a468ba2ba77aafa2a572c8947d414e74604a7c1c6e68a0b87fbfce4f8854dd61"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $bytes0 = { 33 D8 8B C3 C1 E8 05 03 D8 8B C3 C1 E0 04 33 D8 8B C3 C1 E8 11 03 D8 8B C3 C1 E0 19 33 D8 8B C3 C1 E8 06 03 C3 }
        $bytes1 = { 81 F9 8E 4E 0E EC 74 10 81 F9 AA FC 0D 7C 74 08 81 F9 54 CA AF 91 75 43 }
    condition:
        all of them
}

