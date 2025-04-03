rule Windows_Ransomware_Agenda_d7b1af3f {
    meta:
        id = "3PwYsMeZvNX1vNISsfTwob"
        fingerprint = "v1_sha256_a68330bf98ae200ff2d0da51836436f2bdff5c10eb4e0145502f688055980493"
        version = "1.0"
        date = "2024-09-10"
        modified = "2024-09-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Agenda"
        reference_sample = "117fc30c25b1f28cd923b530ab9f91a0a818925b0b89b8bc9a7f820a9e630464"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $ = "-RECOVER-README.txt"
        $ = "/c vssadmin.exe delete shadows /all /quiet"
        $ = "directory_black_list"
        $ = "C:\\Users\\Public\\enc.exe"
    condition:
        all of them
}

