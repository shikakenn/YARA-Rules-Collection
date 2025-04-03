
rule aspack {
    meta:
        id = "3zJ5a1MAo8LW7I6eb65M6u"
        fingerprint = "v1_sha256_0ddfa68e82558680e727bd5e1d18c2803cced9bea15c7f75ad49efa901d4869f"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "ASPack packed file"
        category = "INFO"
        block = false
        quarantine = false

    strings:
        $mz = "MZ"
        $aspack_section = {2E61737061636B00}
        $adata_section = {2E61646174610000}

    condition:
        $mz at 0 and $aspack_section at 0x248 and $adata_section at 0x270
}

