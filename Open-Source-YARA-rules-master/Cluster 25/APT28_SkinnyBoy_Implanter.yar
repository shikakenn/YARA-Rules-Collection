import "pe"
rule APT28_SkinnyBoy_Implanter: RUSSIAN THREAT ACTOR {
    meta:
        id = "2FKpM51m5lmgG4j8qFtQVh"
        fingerprint = "v1_sha256_f5b8944910297988ecf5aecf23d20c384cf141a3a0972baadfacc4969dc46e7c"
        version = "1.0"
        date = "2021-05-24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cluster25"
        description = "NA"
        category = "INFO"
        report = "HTTPS://21649046.FS1.HUBSPOTUSERCONTENT-NA1.NET/HUBFS/21649046/2021-05_FANCYBEAR.PDF"
        hash = "ae0bc3358fef0ca2a103e694aa556f55a3fed4e98ba57d16f5ae7ad4ad583698"

strings:
$enc_string = {F3 0F 7E 05 ?? ?? ?? ?? 6? [5] 6A ?? 66 [6] 66 [7] F3 0F 7E 05 ?? ?? ?? ?? 8D
85 [4] 6A ?? 50 66 [7] E8}
$heap_ops = {8B [1-5] 03 ?? 5? 5? 6A 08 FF [1-6] FF ?? ?? ?? ?? ?? [0-6] 8B ?? [0-6] 8?}
$xor_cycle = { 8A 8C ?? ?? ?? ?? ?? 30 8C ?? ?? ?? ?? ?? 42 3B D0 72 }
condition:
uint16(0) == 0x5a4d and pe.is_dll() and filesize < 100KB and $xor_cycle and $heap_ops and
$enc_string
}
