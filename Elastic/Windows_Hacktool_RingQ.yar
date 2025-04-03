rule Windows_Hacktool_RingQ_b9715540 {
    meta:
        id = "2xIVLc2aNwcDBSsWptUw8G"
        fingerprint = "v1_sha256_80d693c43a7026d28121e035ae875689512fd46d7f06c3f469b83d6fe707f36b"
        version = "1.0"
        date = "2024-06-28"
        modified = "2024-07-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Hacktool.RingQ"
        reference_sample = "450e01c32618cd4e4a327147896352ed1b34dca9fb28389dba450acf95f8b735"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "Loading Dir main.txt ..." ascii fullword
        $a2 = "Loading LocalFile ..." ascii fullword
        $a3 = "No Find main,txt and StringTable ..." ascii fullword
        $a4 = "https://github.com/T4y1oR/RingQ"
        $a5 = "RingQ :)" ascii fullword
        $a6 = "1. Create.exe fscan.exe" ascii fullword
        $a7 = "C:/Users/username/Documents/file.txt" ascii fullword
    condition:
        2 of them
}

