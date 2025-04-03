private rule HTMLVariant : FakeM Family HTML Variant
{
    meta:
        id = "7DHMUO7VxkBIKiju5MRPd6"
        fingerprint = "v1_sha256_0cdacad9ffd00bc1b23e51245503419141bc6d783b253241e1017fcd5586befb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Identifier for html variant of FAKEM"
        category = "INFO"
        last_updated = "2014-05-20"

    strings:
        // decryption loop
        $s1 = { 8B 55 08 B9 00 50 00 00 8D 3D ?? ?? ?? 00 8B F7 AD 33 C2 AB 83 E9 04 85 C9 75 F5 }
        //mov byte ptr [ebp - x] y, x: 0x10-0x1 y: 0-9,A-F
        $s2 = { C6 45 F? (3?|4?) }

    condition:
        $s1 and #s2 == 16

}

//todo: need rules for other variants
rule FakeM : Family
{
    meta:
        id = "39RSu7KaIlbrelWopcjybK"
        fingerprint = "v1_sha256_b017ec27bee4c6e0baad882153e94d7dcb01ae12a616f9a6334f68a50c0c7103"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "FakeM"
        category = "INFO"
        last_updated = "2014-07-03"

    condition:
        HTMLVariant


}

rule FAKEMhtml : Variant
{
    meta:
        id = "68dWky1L3TKdVWJP8jc2Kd"
        fingerprint = "v1_sha256_b017ec27bee4c6e0baad882153e94d7dcb01ae12a616f9a6334f68a50c0c7103"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Katie Kleemola"
        description = "Rule for just the HTML Variant"
        category = "INFO"
        last_updated = "2014-07-10"

    condition:
        HTMLVariant
}
