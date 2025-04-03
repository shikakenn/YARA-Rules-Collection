rule apt_c16_win_swisyn : Memory
{
    meta:
        id = "583uaEtvn03F0yI7IYTAqg"
        fingerprint = "v1_sha256_2fa29d3b17aa37501131132640953645d0089c9bc5ec13ffed7a498ad89c1558"
        version = "1.0"
        date = "2015/01/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dragonthreatlab"
        description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
        category = "INFO"
        reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
        md5 = "a6a18c846e5179259eba9de238f67e41"

  strings:
    $mz = {4D 5A}
    $str1 = "/ShowWU" ascii
    $str2 = "IsWow64Process"
    $str3 = "regsvr32 "
    $str4 = {8A 11 2A 55 FC 8B 45 08 88 10 8B 4D 08 8A 11 32 55 FC 8B 45 08 88 10}
  condition:
    $mz at 0 and all of ($str*)
}
