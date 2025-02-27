rule Windows_Hacktool_SharpMove_05e28928 {
    meta:
        id = "1KJ6btNh3jfYAwRP6pshPG"
        fingerprint = "v1_sha256_021a56dd47d9929e71b82b00d24aa8969a31945681dcf414c69b8d175fb0b6eb"
        version = "1.0"
        date = "2022-11-20"
        modified = "2023-01-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpMove"
        reference_sample = "051f60f9f4665b96f764810defe9525ae7b4f9898249b83a23094cee63fa0c3b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" ascii wide nocase
        $print_str0 = "[X]  Failed to connecto to WMI: {0}" ascii wide fullword
        $print_str1 = "[+] Executing DCOM ShellBrowserWindow   : {0}" ascii wide fullword
        $print_str2 = "[+]  User credentials  : {0}" ascii wide fullword
        $print_str3 = "[+] Executing DCOM ExcelDDE   : {0}" ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

