rule Windows_Trojan_SysJoker_1ef19a12 {
    meta:
        id = "3ISRPhjyoStCTR5VJvTimI"
        fingerprint = "v1_sha256_25bd58d546549d208f9f95f4c27d1e58f86f87750dae1e293544cc92b25f8b32"
        version = "1.0"
        date = "2022-02-17"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SysJoker"
        reference_sample = "61df74731fbe1eafb2eb987f20e5226962eeceef010164e41ea6c4494a4010fc"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "';Write-Output \"Time taken : $((Get - Date).Subtract($start_time).Seconds) second(s)\"" ascii fullword
        $a2 = "powershell.exe Expand-Archive -LiteralPath '" ascii fullword
        $a3 = "powershell.exe Invoke-WebRequest -Uri '" ascii fullword
        $a4 = "\\recoveryWindows.zip" ascii fullword
    condition:
        3 of them
}

rule Windows_Trojan_SysJoker_34559bcd {
    meta:
        id = "5fs7XAVEWXVpebuT5HLx0t"
        fingerprint = "v1_sha256_ebe7f6037f14e37b6efe81614c06c6d26fe0cc17d0475b8b19715f80d0d9aad3"
        version = "1.0"
        date = "2022-02-21"
        modified = "2022-04-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Trojan.SysJoker"
        reference_sample = "1ffd6559d21470c40dcf9236da51e5823d7ad58c93502279871c3fe7718c901c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\\txc1.txt\" && type \"" ascii fullword
        $a2 = "tempo1.txt" nocase
        $a3 = "user_token="
        $a4 = "{\"status\":\"success\",\"result\":\"" ascii fullword
        $a5 = "\",\"av\":\"" ascii fullword
        $a6 = "aSwpEHc0QyIxPRAqNmkeEwskMW8HODkkYRkCICIrJysHNmtlIzQiChMiGAxzQg==" ascii fullword
        $a7 = "ESQuBT8uQyglJy4QOicGXDMiayYtPQ==" ascii fullword
    condition:
        4 of them
}

