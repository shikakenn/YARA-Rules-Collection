
rule upx {
    meta:
        id = "5A2aJ11PtVD2DlL8AAY38P"
        fingerprint = "v1_sha256_8771e23410d5347d249aded8ac96ad90ad678044163b64f5f8db021e6f471cea"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "UPX packed file"
        category = "INFO"
        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}
        $upx_sig = "UPX!"

    condition:
        $mz at 0 and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024)
}

