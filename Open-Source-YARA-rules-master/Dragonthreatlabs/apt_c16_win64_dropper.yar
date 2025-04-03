rule apt_c16_win64_dropper : Dropper
{
    meta:
        id = "1drjCN8aTT6Dcnps7ffKB5"
        fingerprint = "v1_sha256_df905711eca68c698ad6340e88ae99fdcae918c86ec2b7c26b62eead54fef892"
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

    strings:
        $mz = { 4D 5A }
        $str1 = "clbcaiq.dll" ascii
        $str2 = "profapi_104" ascii
        $str3 = "\\Microsoft\\wuauclt\\wuauclt.dat" ascii
        $str4 = { 0F B6 0A 48 FF C2 80 E9 03 80 F1 03 49 FF C8 88 4A FF 75 EC }

    condition:
        $mz at 0 and all of ($str*)
}
