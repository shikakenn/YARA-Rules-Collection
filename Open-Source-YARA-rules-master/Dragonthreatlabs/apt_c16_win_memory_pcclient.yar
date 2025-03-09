import "pe"


rule apt_c16_win_memory_pcclient : Memory APT 
{
    meta:
        id = "4BOOK9sjibZaPHGNJXVO0R"
        fingerprint = "v1_sha256_e863fcbcbde61db569a34509061732371143f38734a0213dc856dc3c9188b042"
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
        md5 = "ec532bbe9d0882d403473102e9724557"

  strings:
    $str1 = "Kill You" ascii
    $str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
    $str3 = "%4.2f  KB" ascii
    $encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}  
  condition:
    all of them
}
