rule crime_ransomware_windows_GPGQwerty

{
    meta:
        id = "3S9qGuPxwDpmomjBXbgjnq"
        fingerprint = "v1_sha256_8e77895cb8e7f33707c5080780a49cb4bf1d35aa7a8df829fdc7a93319ce3897"
        version = "1.0"
        date = "2018-03-21"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee Labs"
        description = "Detect GPGQwerty ransomware"
        category = "MALWARE"
        malware_type = "RANSOMWARE"
        actor_type = "CRIMEWARE"
        reference = "https://securingtomorrow.mcafee.com/mcafee-labs/ransomware-takes-open-source-path-encrypts-gnu-privacy-guard/"
        rule_version = "v1"
        malware_family = "Ransom:W32/GPGQwerty"
        actor_group = "Unknown"

    strings:

        $a = "gpg.exe –recipient qwerty  -o"
        $b = "%s%s.%d.qwerty"
        $c = "del /Q /F /S %s$recycle.bin"
        $d = "cryz1@protonmail.com"

    condition:

        all of them
}
