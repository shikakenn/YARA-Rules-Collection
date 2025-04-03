rule Windows_Hacktool_SharpLAPS_381c3f40 {
    meta:
        id = "3DT1XwiwoOvgWyojQJeo4M"
        fingerprint = "v1_sha256_d94f9e4200a63283346919c121873130ad90e4ad5979c017cb71dc0cc910a64a"
        version = "1.0"
        date = "2022-12-22"
        modified = "2022-12-22"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpLAPS"
        reference_sample = "ef0d508b3051fe6f99ba55202a17237f29fdbc0085e3f5c99b1aef52c8ebe425"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "1e0986b4-4bf3-4cea-a885-347b6d232d46" ascii wide nocase
        $str_name = "SharpLAPS.exe" ascii wide
        $str0 = "Using the current session" ascii wide
        $str1 = "Extracting LAPS password" ascii wide
        $str2 = "(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=" ascii wide
        $str4 = "Machine" ascii wide
        $str5 = "sAMAccountName" ascii wide
        $str6 = "ms-Mcs-AdmPwd" ascii wide
    condition:
        $guid or 6 of ($str*)
}

