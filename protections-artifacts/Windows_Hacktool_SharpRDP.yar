rule Windows_Hacktool_SharpRDP_80895fcb {
    meta:
        id = "1y5YVOvsFcQdg77XWdEPM8"
        fingerprint = "v1_sha256_ef9a92f2ed29f508dca591e9c65a6ce0013ccdfd0c62770e8840be2f3ee5982e"
        version = "1.0"
        date = "2022-11-20"
        modified = "2023-01-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpRDP"
        reference_sample = "6e909861781a8812ee01bc59435fd73fd34da23fa9ad6d699eefbf9f84629876"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "F1DF1D0F-FF86-4106-97A8-F95AAF525C54" ascii wide nocase
        $print_str0 = "[+] Another user is logged on, asking to take over session" ascii wide fullword
        $print_str1 = "[+] Execution priv type   :  {0}" ascii wide fullword
        $print_str2 = "[+] Sleeping for 30 seconds" ascii wide fullword
        $print_str3 = "[X] Error: A password is required" ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

