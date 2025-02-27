rule Windows_Hacktool_SharpAppLocker_9645cf22 {
    meta:
        id = "4QmLrZ839lwSZqRIzJ6PTB"
        fingerprint = "v1_sha256_cb72ecf7715b288acddac51dab091d84c64e3bd30276cba38a0d773e6693875c"
        version = "1.0"
        date = "2022-11-20"
        modified = "2023-01-11"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.SharpAppLocker"
        reference_sample = "0f7390905abc132889f7b9a6d5b42701173aafbff5b8f8882397af35d8c10965"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $guid = "FE102D27-DEC4-42E2-BF69-86C79E08B67D" ascii wide nocase
        $print_str0 = "[+] Output written to:" ascii wide fullword
        $print_str1 = "[!] You can only select one Policy at the time." ascii wide fullword
        $print_str2 = "SharpAppLocker.exe --effective --allow --rules=\"FileHashRule,FilePathRule\" --outfile=\"C:\\Windows\\Tasks\\Rules.json\"" ascii wide fullword
    condition:
        $guid or all of ($print_str*)
}

