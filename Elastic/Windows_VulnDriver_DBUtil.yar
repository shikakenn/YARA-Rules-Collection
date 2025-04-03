rule Windows_VulnDriver_DBUtil_ffe07c79 {
    meta:
        id = "4EHGDQX9qvOOopxHS13XS4"
        fingerprint = "v1_sha256_18b1c93c395b105f446b4c968441e0a43e42b1bd7efcf6501a89eb92cbd21824"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.DBUtil"
        reference_sample = "87e38e7aeaaaa96efe1a74f59fca8371de93544b7af22862eb0e574cec49c7c3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\DBUtilDrv2_32.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

rule Windows_VulnDriver_DBUtil_852ba283 {
    meta:
        id = "2IWb4vbHbu7JhaZJrfSab2"
        fingerprint = "v1_sha256_78acd081c2517f9c53cb311481c0cc40cc3699b222afc290da1a3698e7bf75b7"
        version = "1.0"
        date = "2022-04-04"
        modified = "2022-04-04"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.VulnDriver.DBUtil"
        reference_sample = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $str1 = "\\DBUtilDrv2_64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $str1
}

