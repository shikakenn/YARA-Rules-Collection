rule Rana_Android_resources {
    meta:
        id = "7eTUWBxBsaayQoPeXoUidt"
        fingerprint = "v1_sha256_4222373a74da46ef5f1a94416934431fbc2f1f2b87115babf51830d200dda189"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "ReversingLabs"
        description = "NA"
        category = "INFO"
        reference = "https://blog.reversinglabs.com/blog/rana-android-malware"

strings:
        $res1 = "res/raw/cng.cn" fullword wide ascii
        $res2 = "res/raw/att.cn" fullword wide ascii
        $res3 = "res/raw/odr.od" fullword wide ascii
condition:
        any of them /* any string in the rule */
}
