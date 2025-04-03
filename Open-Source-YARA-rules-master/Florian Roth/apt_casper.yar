
/* State-sponsored Casper Malware Rules by @4nc4p - attribution and analysis by @pinkflawd @r00tbsd @circl_lu */

rule Casper_Backdoor_x86 {
    meta:
        id = "11dz5hb9MmyzQwZvqlseVf"
        fingerprint = "v1_sha256_74f8f2ef39eca9507ca377607f72d638005bee174e2e4047e403a817de153f15"
        version = "1.0"
        score = 80
        date = "2015/03/05"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Casper French Espionage Malware - Win32/ProxyBot.B - x86 Payload http://goo.gl/VRJNLo"
        category = "INFO"
        reference = "http://goo.gl/VRJNLo"
        hash = "f4c39eddef1c7d99283c7303c1835e99d8e498b0"

    strings:
        $s1 = "\"svchost.exe\"" fullword wide
        $s2 = "firefox.exe" fullword ascii
        $s3 = "\"Host Process for Windows Services\"" fullword wide
        
        $x1 = "\\Users\\*" fullword ascii
        $x2 = "\\Roaming\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
        $x3 = "\\Mozilla\\Firefox\\Profiles\\*" fullword ascii
        $x4 = "\\Documents and Settings\\*" fullword ascii
        
        $y1 = "%s; %S=%S" fullword wide
        $y2 = "%s; %s=%s" fullword ascii
        $y3 = "Cookie: %s=%s" fullword ascii
        $y4 = "http://%S:%d" fullword wide
        
        $z1 = "http://google.com/" fullword ascii
        $z2 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MALC)" fullword ascii
        $z3 = "Operating System\"" fullword wide
    condition:
        ( all of ($s*) ) or
        ( 3 of ($x*) and 2 of ($y*) and 2 of ($z*) )
}

rule Casper_EXE_Dropper {
    meta:
        id = "3SB8z5R3z61wWT9iIa6Ad8"
        fingerprint = "v1_sha256_8ffba5598078fdadf2d9e8ee7fe0fef8b3b89517490a379d46cab33cd0036d6e"
        version = "1.0"
        score = 80
        date = "2015/03/05"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Casper French Espionage Malware - Win32/ProxyBot.B - Dropper http://goo.gl/VRJNLo"
        category = "INFO"
        reference = "http://goo.gl/VRJNLo"
        hash = "e4cc35792a48123e71a2c7b6aa904006343a157a"

    strings:
        $s0 = "<Command>" fullword ascii
        $s1 = "</Command>" fullword ascii
        $s2 = "\" /d \"" fullword ascii
        $s4 = "'%s' %s" fullword ascii
        $s5 = "nKERNEL32.DLL" fullword wide
        $s6 = "@ReturnValue" fullword wide
        $s7 = "ID: 0x%x" fullword ascii
        $s8 = "Name: %S" fullword ascii
    condition:
        7 of them
}

rule Casper_Included_Strings {
    meta:
        id = "wdTqGjeisuuQgUYmDEZnc"
        fingerprint = "v1_sha256_185375a53dff72635c3ac1bd5b4f143f161dd321afff0c05af896ca67585b9b5"
        version = "1.0"
        score = 50
        date = "2015/03/06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Casper French Espionage Malware - String Match in File - http://goo.gl/VRJNLo"
        category = "INFO"
        reference = "http://goo.gl/VRJNLo"

    strings:
        $a0 = "cmd.exe /C FOR /L %%i IN (1,1,%d) DO IF EXIST"
        $a1 = "& SYSTEMINFO) ELSE EXIT"
        
        $mz = { 4d 5a }
        $c1 = "domcommon.exe" wide fullword							// File Name
        $c2 = "jpic.gov.sy" fullword 								// C2 Server
        $c3 = "aiomgr.exe" wide fullword							// File Name
        $c4 = "perfaudio.dat" fullword								// Temp File Name
        $c5 = "Casper_DLL.dll" fullword								// Name 
        $c6 = { 7B 4B 59 DE 37 4A 42 26 59 98 63 C6 2D 0F 57 40 } 	// Decryption Key
        $c7 = "{4216567A-4512-9825-7745F856}" fullword 				// Mutex
    condition:
        all of ($a*) or
        ( $mz at 0 ) and ( 1 of ($c*) )
}

rule Casper_SystemInformation_Output {
    meta:
        id = "1gqaR2PfeJT9OmzUb81re1"
        fingerprint = "v1_sha256_83c6216bc3e7fadfe81b9bbaca7b14e3398e972f8298c99a8eb576a40e4b4e1b"
        version = "1.0"
        score = 70
        date = "2015/03/06"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Casper French Espionage Malware - System Info Output - http://goo.gl/VRJNLo"
        category = "INFO"
        reference = "http://goo.gl/VRJNLo"

    strings:
        $a0 = "***** SYSTEM INFORMATION ******"
        $a1 = "***** SECURITY INFORMATION ******"
        $a2 = "Antivirus: "
        $a3 = "Firewall: "
        $a4 = "***** EXECUTION CONTEXT ******"
        $a5 = "Identity: "
        $a6 = "<CONFIG TIMESTAMP="
    condition:
        all of them
}
