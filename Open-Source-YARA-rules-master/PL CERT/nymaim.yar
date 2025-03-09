rule nymaim: trojan
{
    meta:
        id = "7P0mBLktVZkpLdnokUb1RP"
        fingerprint = "v1_sha256_3dd8c75a4545597f9bb933a30e121226c5800168ecb9104f2cea4d9b466a1d90"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mak"
        description = "NA"
        category = "INFO"
        reference = "https://www.cert.pl/en/news/single/nymaim-revisited/"

    strings:
       $call_obfu_xor = {55 89 E5 5? 8B ?? 04 89 ?? 10 8B ?? 0C 33 ?? 08 E9 }
       $call_obfu_add = {55 89 E5 5? 8B ?? 04 89 ?? 10 8B ?? 0C 03 ?? 08 E9 }
       $call_obfu_sub = {55 89 E5 5? 8B ?? 04 89 ?? 10 8B ?? 0C 2b ?? 08 E9 }
       $nym_get_cnc = {E8 [4] C7 45 ?? [4] C7 45 ?? [4] 83 ??}//3D[4] 01 74 4E E8}
       $nym_get_cnc2 ={E8 [4] C7 45 ?? [4] 89 [5] 89 [5] C7 45 ?? [4] 83 ??}
       $nym_check_unp = {C7 45 ?? [4] 83 3D [3] 00 01 74 }
       $set_cfg_addr = {FF 75 ?? 8F 05 [4] FF 75 08 8F 05 [4] 68 [4] 5? 68 [4] 68 [4] E8}

    condition:
       (
            /* orig */
            (2 of ($call_obfu*)) and (
                /* old versions */
                $nym_check_unp or $nym_get_cnc2 or $nym_get_cnc or
                /* new version */
                $set_cfg_addr
            )
       )
}
