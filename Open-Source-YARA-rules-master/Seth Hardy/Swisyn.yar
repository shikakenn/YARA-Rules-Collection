rule apt_c16_win_wateringhole 
{
    meta:
        id = "7l6RsI3FPca4ONnedVJHa5"
        fingerprint = "v1_sha256_e866499ec77984f5bacf3f5e352393b63e0dd08fd8fd57b4990292a1dc7fbcbe"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dragonthreatlab "
        description = "Detects code from APT wateringhole"
        category = "INFO"

  strings:
    $str1 = "function runmumaa()"
    $str2 = "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String("
    $str3 = "function MoSaklgEs7(k)"
  condition:
    any of ($str*)
}
rule apt_c16_win_swisyn 
{
    meta:
        id = "4G7dFvQL8sUnDAFUcBpWmk"
        fingerprint = "v1_sha256_2fa29d3b17aa37501131132640953645d0089c9bc5ec13ffed7a498ad89c1558"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dragonthreatlab"
        description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
        category = "INFO"
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
rule apt_c16_win32_dropper 
{
    meta:
        id = "yy9NBUA5VYadedaJ3XXhY"
        fingerprint = "v1_sha256_bb29bcf5e62cb1a55d7f0cb87b53bace26b99f858513dc4e544d531f70f54281"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dragonthreatlab"
        description = "APT malware used to drop PcClient RAT"
        category = "INFO"
        md5 = "ad17eff26994df824be36db246c8fb6a"

  strings:
    $mz = {4D 5A}
    $str1 = "clbcaiq.dll" ascii
    $str2 = "profapi_104" ascii
    $str3 = "/ShowWU" ascii
    $str4 = "Software\\Microsoft\\Windows\\CurrentVersion\\" ascii
    $str5 = {8A 08 2A CA 32 CA 88 08 40 4E 75 F4 5E}
  condition:
    $mz at 0 and all of ($str*)
}
rule apt_c16_win64_dropper 
{
    meta:
        id = "617XQlqVbXgfHYBX6b547C"
        fingerprint = "v1_sha256_df905711eca68c698ad6340e88ae99fdcae918c86ec2b7c26b62eead54fef892"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dragonthreatlab"
        description = "APT malware used to drop PcClient RAT"
        category = "INFO"
        md5 = "ad17eff26994df824be36db246c8fb6a"

  strings:
    $mz = {4D 5A}
    $str1 = "clbcaiq.dll" ascii
    $str2 = "profapi_104" ascii
    $str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
    $str4 = {0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC}
  condition:
    $mz at 0 and all of ($str*)
}
rule apt_c16_win_disk_pcclient 
{
    meta:
        id = "34Y508LIPA3a3PwJCJFoch"
        fingerprint = "v1_sha256_47e9588ef1f350ee0d2aecc7686d9e4df1ad6c19f27d749e31340eff7e31adcb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dragonthreatlab "
        description = "Encoded version of pcclient found on disk"
        category = "INFO"
        md5 = "55f84d88d84c221437cd23cdbc541d2e"

  strings:
    $header = {51 5C 96 06 03 06 06 06 0A 06 06 06 FF FF 06 06 BE 06 06 06 06 06 06 06 46 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 EE 06 06 06 10 1F BC 10 06 BA 0D D1 25 BE 05 52 D1 25 5A 6E 6D 73 26 76 74 6F 67 74 65 71 26 63 65 70 70 6F 7A 26 64 69 26 74 79 70 26 6D 70 26 4A 4F 53 26 71 6F 6A 69 30 11 11 0C 2A 06 06 06 06 06 06 06 73 43 96 1B 37 24 00 4E 37 24 00 4E 37 24 00 4E BA 40 F6 4E 39 24 00 4E 5E 41 FA 4E 33 24 00 4E 5E 41 FC 4E 39 24 00 4E 37 24 FF 4E 0D 24 00 4E FA 31 A3 4E 40 24 00 4E DF 41 F9 4E 36 24 00 4E F6 2A FE 4E 38 24 00 4E DF 41 FC 4E 38 24 00 4E 54 6D 63 6E 37 24 00 4E 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 06 56 49 06 06 52 05 09 06 5D 87 8C 5A 06 06 06 06 06 06 06 06 E6 06 10 25 0B 05 08 06 06 1C 06 06 06 1A 06 06 06 06 06 06 E5 27 06 06 06 16 06 06 06 36 06 06 06 06 06 16 06 16 06 06 06 04 06 06 0A 06 06 06 06 06 06 06 0A 06 06 06 06 06 06 06 06 76 06 06 06 0A 06 06 06 06 06 06 04 06 06 06 06 06 16 06 06 16 06 06}
  condition:
    $header at 0
}
rule apt_c16_win_memory_pcclient 
{
    meta:
        id = "jGk1zBkGaHEuKq9oEWJ1d"
        fingerprint = "v1_sha256_e863fcbcbde61db569a34509061732371143f38734a0213dc856dc3c9188b042"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dragonthreatlab "
        description = "File matching the md5 above tends to only live in memory, hence the lack of MZ header check."
        category = "INFO"
        md5 = "ec532bbe9d0882d403473102e9724557"

  strings:
    $str1 = "Kill You" ascii
    $str2 = "%4d-%02d-%02d %02d:%02d:%02d" ascii
    $str3 = "%4.2f  KB" ascii
    $encodefunc = {8A 08 32 CA 02 CA 88 08 40 4E 75 F4}  
  condition:
    all of them
}
