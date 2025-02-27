rule Windows_Hacktool_SharPersist_06606812 {
    meta:
        id = "5e5KtaYZm1YCWcVdpk24Hk"
        fingerprint = "v1_sha256_ddabfb54422f6fb2ad6999b724b1d8f186adf71f96f01a8770715029529e869a"
        version = "1.0"
        date = "2022-10-20"
        modified = "2022-11-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.Sharpersist"
        reference_sample = "e9711f47cf9171f79bf34b342279f6fd9275c8ae65f3eb2c6ebb0b8432ea14f8"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "9D1B853E-58F1-4BA5-AEFC-5C221CA30E48" ascii wide nocase
        $print_str0 = "schtaskbackdoor: backdoor scheduled task" ascii wide
        $print_str1 = "schtaskbackdoor -m list -n <schtask name>" ascii wide
        $print_str2 = "SharPersist" ascii wide
        $print_str3 = "[+] SUCCESS: Keepass persistence backdoor added" ascii wide
    condition:
        $guid or all of ($print_str*)
}

