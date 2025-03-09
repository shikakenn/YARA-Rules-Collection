/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-03-30
    Identifier: TempRacer
*/

/* Rule Set ----------------------------------------------------------------- */

rule TempRacer {
    meta:
        id = "6KeNTzZA1yv91IFgI1mV1X"
        fingerprint = "v1_sha256_37355456e13ea9fa6429b68970e0450f4ddbd8da81c070a0383b1e048a05e35a"
        version = "1.0"
        date = "2016-03-30"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects privilege escalation tool - file TempRacer.exe"
        category = "INFO"
        reference = "http://www.darknet.org.uk/2016/03/tempracer-windows-privilege-escalation-tool/"
        hash = "e17d80c4822d16371d75e1440b6ac44af490b71fbee1010a3e8a5eca94d22bb3"

    strings:
        $s1 = "\\obj\\Release\\TempRacer.pdb" ascii
        $s2 = "[+] Injecting into " fullword wide
        $s3 = "net localgroup administrators alex /add" fullword wide
        $s4 = "[+] File: {0} renamed to {1}" fullword wide
        $s5 = "[+] Blocking " fullword wide
    condition:
        ( uint16(0) == 0x5a4d and filesize < 25KB and 1 of them ) or ( 4 of them )
}
