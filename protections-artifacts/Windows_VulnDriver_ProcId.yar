rule Windows_VulnDriver_ProcId_86605fa9 {
    meta:
        id = "7DErgQjw5LR82wcWVdZlrP"
        fingerprint = "v1_sha256_882cdbd267d812e77e68e7080f1fca0ca3d7e75ab84c583c3ec148894b1cf644"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.ProcId"
        reference_sample = "b03f26009de2e8eabfcf6152f49b02a55c5e5d0f73e01d48f5a745f93ce93a29"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\piddrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

