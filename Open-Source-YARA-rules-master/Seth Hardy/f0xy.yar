rule ws_f0xy_downloader {
    meta:
        id = "VDWDPTSqmz5tT9QiZtxMk"
        fingerprint = "v1_sha256_ca5dd7e4ea04606e566ddee61534dfc0324bf3e34e3cfebce4e5194b0bd4cd6d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Nick Griffin (Websense)"
        description = "f0xy malware downloader"
        category = "INFO"

  strings:
    $mz="MZ"
    $string1="bitsadmin /transfer"
    $string2="del rm.bat"
    $string3="av_list="
  
  condition:
    ($mz at 0) and (all of ($string*))
}
