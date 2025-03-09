rule apt_c16_win32_dropper : Dropper
{
    meta:
        id = "75iarYxKMrS98i3uqDRjZO"
        fingerprint = "v1_sha256_bb29bcf5e62cb1a55d7f0cb87b53bace26b99f858513dc4e544d531f70f54281"
        version = "1.0"
        date = "2015/01/11"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "@dragonthreatlab"
        description = "APT malware used to drop PcClient RAT"
        category = "INFO"
        reference = "http://blog.dragonthreatlabs.com/2015/01/dtl-12012015-01-hong-kong-swc-attack.html"
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
