rule Windows_AttackSimulation_Hovercraft_f5c7178f {
    meta:
        id = "2clcSrA0CjQCDduKXWgS4x"
        fingerprint = "v1_sha256_e707e89904a5fa4d30f94bfc625b736a411df6bb055c0e40df18ae65025a3740"
        version = "1.0"
        date = "2022-05-23"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "046645b2a646c83b4434a893a0876ea9bd51ae05e70d4e72f2ccc648b0f18cb6"
        threat_name = "Windows.AttackSimulation.Hovercraft"
        severity = 1
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "MyHovercraftIsFullOfEels" wide fullword
        $a2 = "WinHttp.dll" fullword
    condition:
        all of them
}

