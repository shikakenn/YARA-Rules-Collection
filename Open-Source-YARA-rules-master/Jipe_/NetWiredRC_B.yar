rule NetWiredRC_B : rat 
{
    meta:
        id = "7Gb7MNFH1FO3hRyYYLkbR3"
        fingerprint = "v1_sha256_fe7d383c31f52f1667721a8593587b2f1c1120fe7fa80ea9b9e63e5090b0b50c"
        version = "1.1"
        date = "2014-12-23"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "NetWiredRC"
        category = "INFO"
        filetype = "memory"

    strings:
        $mutex = "LmddnIkX"

        $str1 = "%s.Identifier"
        $str2 = "%d:%I64u:%s%s;"
        $str3 = "%s%.2d-%.2d-%.4d"
        $str4 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
        $str5 = "%.2d/%.2d/%d %.2d:%.2d:%.2d"
        
        $klg1 = "[Backspace]"
        $klg2 = "[Enter]"
        $klg3 = "[Tab]"
        $klg4 = "[Arrow Left]"
        $klg5 = "[Arrow Up]"
        $klg6 = "[Arrow Right]"
        $klg7 = "[Arrow Down]"
        $klg8 = "[Home]"
        $klg9 = "[Page Up]"
        $klg10 = "[Page Down]"
        $klg11 = "[End]"
        $klg12 = "[Break]"
        $klg13 = "[Delete]"
        $klg14 = "[Insert]"
        $klg15 = "[Print Screen]"
        $klg16 = "[Scroll Lock]"
        $klg17 = "[Caps Lock]"
        $klg18 = "[Alt]"
        $klg19 = "[Esc]"
        $klg20 = "[Ctrl+%c]"

    condition: 
        $mutex or (1 of ($str*) and 1 of ($klg*))
}
