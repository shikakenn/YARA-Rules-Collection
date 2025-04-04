rule Linux_Ransomware_RedAlert_39642d52 {
    meta:
        id = "2RlOl3EdScZp0iILlDBG3M"
        fingerprint = "v1_sha256_fa8fc16f0c8a55dd78781d334d7f55db6aa5e60f76cebf5282150af8ceb08dc3"
        version = "1.0"
        date = "2022-07-06"
        modified = "2022-08-16"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Linux.Ransomware.RedAlert"
        reference_sample = "039e1765de1cdec65ad5e49266ab794f8e5642adb0bdeb78d8c0b77e8b34ae09"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"

    strings:
        $str_ransomnote = "\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\% REDALERT UNIQUE IDENTIFIER START \\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%\\%" ascii fullword
        $str_print = "\t\t\t########\n\t\t\t[ N13V ]\n\t\t\t########\n\n" ascii fullword
        $str_arg = "[info] Catch -t argument. Check encryption time" ascii fullword
        $str_ext = ".crypt658" ascii fullword
        $byte_checkvm = { 48 8B 14 DD ?? ?? ?? ?? 31 C0 48 83 C9 FF FC 48 89 EE 48 89 D7 F2 AE 4C 89 E7 48 F7 D1 E8 }
    condition:
        3 of ($str_*) or ($byte_checkvm and $str_print)
}

