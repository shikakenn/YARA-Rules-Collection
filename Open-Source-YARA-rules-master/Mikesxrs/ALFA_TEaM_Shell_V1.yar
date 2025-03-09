rule ALFA_TEaM_Shell_V1
{
    meta:
        id = "7i2M6juTTl8JjGemQtxYqI"
        fingerprint = "v1_sha256_b2a6236de6f210245fb747cef4e9276fcca6e5e0e37ec0d75011d3049a9b07d5"
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
        $STR1 = "#Iranian Hackers"
        $STR2 = "#Persian Gulf For Ever"
        $STR3 = "#Special Thanks To MadLeets"
        $STR4 = "function alfa("
        $STR5 = "=alfa("
        $STR6 = "#Author Sole Sad & Invisible"
        $STR7 = "#solevisible@gmail.com"
        $STR8 = "#CopyRight 2014"
        
    condition:
        5 of them
}
