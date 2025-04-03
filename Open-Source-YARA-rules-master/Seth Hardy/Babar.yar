rule SNOWGLOBE_Babar_Malware 
{
    meta:
        id = "1NHDOq4XMG4N1iKjeDvn46"
        fingerprint = "v1_sha256_ab7b2a7eed701b196259bf9b9bce329565538f173759a74809a646503167e8eb"
        version = "1.0"
        score = 80
        date = "2015/02/18"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects the Babar Malware used in the SNOWGLOBE attacks - file babar.exe"
        category = "INFO"
        reference = "http://motherboard.vice.com/read/meet-babar-a-new-malware-almost-certainly-created-by-france"
        hash = "27a0a98053f3eed82a51cdefbdfec7bb948e1f36"

    strings:
        $mz = { 4d 5a }
        $z0 = "admin\\Desktop\\Babar64\\Babar64\\obj\\DllWrapper" ascii fullword
        $z1 = "User-Agent: Mozilla/4.0 (compatible; MSI 6.0;" ascii fullword
        $z2 = "ExecQueryFailled!" fullword ascii
        $z3 = "NBOT_COMMAND_LINE" fullword
        $z4 = "!!!EXTRACT ERROR!!!File Does Not Exists-->[%s]" fullword

        $s1 = "/s /n %s \"%s\"" fullword ascii
        $s2 = "%%WINDIR%%\\%s\\%s" fullword ascii
        $s3 = "/c start /wait " fullword ascii
        $s4 = "(D;OICI;FA;;;AN)(A;OICI;FA;;;BG)(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)" ascii

        $x1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" fullword ascii
        $x2 = "%COMMON_APPDATA%" fullword ascii
        $x4 = "CONOUT$" fullword ascii
        $x5 = "cmd.exe" fullword ascii
        $x6 = "DLLPATH" fullword ascii

    condition:
        ( $mz at 0 ) and filesize < 1MB and
        (( 1 of ($z*) and 1 of ($x*) ) or( 3 of ($s*) and 4 of ($x*) ))
}
