private rule iexpl0reCode : iexpl0ree Family 
{
    meta:
        id = "53NHgKibs6Kn2fUvJeU7HB"
        fingerprint = "v1_sha256_804ec3e673ae477c2afdaa657bfc34b2d504f8f7d1eab6c4429d7abceaf5c6f3"
        version = "1.0"
        modified = "2014-07-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "iexpl0re code features"
        category = "INFO"

    strings:
        $ = { 47 83 FF 64 0F 8C 6D FF FF FF 33 C0 5F 5E 5B C9 C3 }
        $ = { 80 74 0D A4 44 41 3B C8 7C F6 68 04 01 00 00 }
        $ = { 8A C1 B2 07 F6 EA 30 04 31 41 3B 4D 10 7C F1 }
        $ = { 47 83 FF 64 0F 8C 79 FF FF FF 33 C0 5F 5E 5B C9 C3 }
        // 88h decrypt
        $ = { 68 88 00 00 00 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        $ = { BB 88 00 00 00 53 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        
    condition:
        any of them
}

private rule iexpl0reStrings : iexpl0re Family
{
    meta:
        id = "4UAxj7EcrcsVlsLgl5VpXu"
        fingerprint = "v1_sha256_ffb4bdea96766d961211d3195bf11160bef134fbb252ee5df1794ce21c769aff"
        version = "1.0"
        modified = "2014-07-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Strings used by iexpl0re"
        category = "INFO"

    strings:
        $ = "%USERPROFILE%\\IEXPL0RE.EXE"
        $ = "\"<770j (("
        $ = "\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IEXPL0RE.LNK"
        $ = "\\Documents and Settings\\%s\\Application Data\\Microsoft\\Internet Explorer\\IEXPL0RE.EXE"
        $ = "LoaderV5.dll"
        // stage 2
        $ = "POST /index%0.9d.asp HTTP/1.1"
        $ = "GET /search?n=%0.9d&"
        $ = "DUDE_AM_I_SHARP-3.14159265358979x6.626176"
        $ = "WHO_A_R_E_YOU?2.99792458x1.25663706143592"
        $ = "BASTARD_&&_BITCHES_%0.8x"
        $ = "c:\\bbb\\eee.txt"
        
    condition:
        any of them

}

rule iexpl0re : Family
{
    meta:
        id = "51wbZJjW5SJUfRlTf0LeDc"
        fingerprint = "v1_sha256_f413acaba90a940f8da81910d880be3d2f2c5a820508af90117be1d5a8c76111"
        version = "1.0"
        modified = "2014-07-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "iexpl0re family"
        category = "INFO"

    condition:
        iexpl0reCode or iexpl0reStrings
        
}
