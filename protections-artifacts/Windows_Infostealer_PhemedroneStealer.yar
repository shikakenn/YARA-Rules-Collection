rule Windows_Infostealer_PhemedroneStealer_bed8ea8a {
    meta:
        id = "1Ml1J5t7CCsjQLlDlQtcKu"
        fingerprint = "v1_sha256_88fc33abfe6c7a611aa0c354645b06e9e74121ffc9a5acd20b4d3a59287489d6"
        version = "1.0"
        date = "2024-03-21"
        modified = "2024-05-08"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ELASTIC"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Infostealer.PhemedroneStealer"
        reference_sample = "38279fdad25c7972be9426cadb5ad5e3ee7e9761b0a41ed617945cb9a3713702"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "<KillDebuggers>b_"
        $a2 = "<Key3Database>b_"
        $a3 = "<IsVM>b_"
        $a4 = "<ParseDatWallets>b_"
        $a5 = "<ParseExtensions>b_"
        $a6 = "<ParseDiscordTokens>b_"
        $b1 = "Phemedrone.Senders"
        $b2 = "Phemedrone.Protections"
        $b3 = "Phemedrone.Extensions"
        $b4 = "Phemedrone.Cryptography"
        $b5 = "Phemedrone-Report.zip"
        $b6 = "Phemedrone Stealer Report"
    condition:
        all of ($a*) or all of ($b*)
}

