rule ALFA_TEaM_Shell_V2
{
    meta:
        id = "4XKJOBXfP5ay4wHRIyTSX4"
        fingerprint = "v1_sha256_eeb3e0989b72b61fc00ddba1b5112864173fcc11c0419f8245fad4ad8cedc2c1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "@X0RC1SM"
        Description = "Looking for ALFA TEaM Shell"
        Reference = "https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html"
        Date = "2017-10-28"

  strings:
        $STR1 = "Alfa Team Starter"
        $STR2 = "Alfa_Protect_Shell"
        $STR3 = "Alfa_Login_Page"
        $STR4 = "$Alfa_Pass = '"
        $STR5 = "Alfa_User = 'alfa'"
        $STR6 = "#Author Sole Sad & Invisible"
        $STR7 = "#solevisible@gmail.com"
        $STR8 = "#Copyright 2014-2016"
        
    condition:
        5 of them
}
