rule Windows_Hacktool_BlackBone_2ff5ec38 {
    meta:
        id = "23DNaypBGxuqmyYzL5RD9v"
        fingerprint = "v1_sha256_0c32bd04460cdf7a56664253992a684c2c684b15ac9ca853b27ab24f07f71607"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.BlackBone"
        reference_sample = "4e3887f950bff034efedd40f1e949579854a24140128246fa6141f2c34de6017"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "BlackBone: %s: ZwCreateThreadEx hThread 0x%X"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

