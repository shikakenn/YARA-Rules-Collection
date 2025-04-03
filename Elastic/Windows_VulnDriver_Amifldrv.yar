rule Windows_VulnDriver_Amifldrv_e387d5ad {
    meta:
        id = "7kQkE1U4ywokiDxgyFgjQm"
        fingerprint = "v1_sha256_14d75b5aff2c82d69b041c654cdc0840f6b6e37a197f5c0c1c2698c9e8eba3e2"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.Amifldrv"
        reference_sample = "fda506e2aa85dc41a4cbc23d3ecc71ab34e06f1def736e58862dc449acbc2330"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\amifldrv64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

