rule urausy_skype_dat {
    meta:
        id = "6qzmzPqqsdqx8KcJZy0b2Z"
        fingerprint = "v1_sha256_0ba5f2d34db8508c1ad5e047552232b4b6c44ec683a543b3355535ffe88a8e77"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "AlienVault Labs"
        description = "Yara rule to match against memory of processes infected by Urausy skype.dat"
        category = "INFO"

    strings:
        $a = "skype.dat" ascii wide
        $b = "skype.ini" ascii wide
        $win1 = "CreateWindow"
        $win2 = "YIWEFHIWQ" ascii wide
        $desk1 = "CreateDesktop"
        $desk2 = "MyDesktop" ascii wide
    condition:
        $a and $b and (all of ($win*) or all of ($desk*))
}
