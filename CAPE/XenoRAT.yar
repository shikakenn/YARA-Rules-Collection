rule XenoRAT {
    meta:
        id = "7MfiYhMhCPon0q1pIFq7SO"
        fingerprint = "v1_sha256_26f520fb69a52d05786fac0e9e38f5db9601da0a3e7768e00975a9684f3560ef"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "jeFF0Falltrades"
        description = "NA"
        category = "INFO"
        cape_type = "XenoRAT payload"

    strings:
        $str_xeno_rat_1 = "xeno rat" wide ascii nocase
        $str_xeno_rat_2 = "xeno_rat" wide ascii nocase
        $str_xeno_update_mgr = "XenoUpdateManager" wide ascii
        $str_nothingset = "nothingset" wide ascii 
        $byte_enc_dec_pre = { 1f 10 8d [4] (0a | 0b) }
        $patt_config = { 72 [3] 70 80 [3] 04 }
    condition:
        4 of them and #patt_config >= 5
 }
