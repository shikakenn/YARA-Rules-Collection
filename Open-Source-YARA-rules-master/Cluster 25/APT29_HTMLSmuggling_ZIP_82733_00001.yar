rule APT29_HTMLSmuggling_ZIP_82733_00001 {
    meta:
        id = "3xLsett3Fq65BrxzgbeQOB"
        fingerprint = "v1_sha256_ec51d08551af64100f0f22ef61470ea930be7a457c5aba84e8e00cd9b423616d"
        version = "1.0"
        date = "2022-05-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cluster25"
        description = "Rule to detect the EnvyScout HTML smuggling with ZIP payload used in the APT29/Nobelium APT29 chain"
        category = "INFO"
        report = "HTTPS://BLOG.CLUSTER25.DUSKRISE.COM/2022/05/13/COZY-SMUGGLED-INTO-THE-BOX"
        hash = "d5c84cbd7dc70e71f3eb24434a58b2f149d0c39faa7e4157552b60c7dbb53d11"

strings:
$s1 = "new Blob("
$s2 = "new Uint8Array("
$s3 = "application/octet-stream"
$t1 = "saveAs("
$t2 = "download("
$r1 = { 66 6F 72 28 76 61 72 20 69 20 3D 20 30 78 30 3B 20 69 20 3C 20 64 5B 27 6C 65 6E 67 74 68 27 5D 3B 20 69 2B 2B 29 20 7B 0A 20 20 20 20 64 5B 69 5D 20 3D 20 64 5B 69 5D }
condition: (filesize > 500KB and all of ($s*) and ($t1 or $t2) and $r1)
}
