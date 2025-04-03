/*
    Yara Rule Set
    Author: YarGen Rule Generator
    Date: 2016-04-20
    Identifier: Metasploit Loader
*/

/* Rule Set ----------------------------------------------------------------- */

rule Metasploit_Loader_RSMudge {
    meta:
        id = "1HLdE9GQbPLdpVvj4VT2jx"
        fingerprint = "v1_sha256_50b1898e3087a5e0876b87179252c452af48e00bbef52297060d70acd90d0133"
        version = "1.0"
        date = "2016-04-20"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a Metasploit Loader by RSMudge - file loader.exe"
        category = "INFO"
        reference = "https://github.com/rsmudge/metasploit-loader"
        hash1 = "afe34bfe2215b048915b1d55324f1679d598a0741123bc24274d4edc6e395a8d"

    strings:
        $s1 = "Could not resolve target" fullword ascii
        $s2 = "Could not connect to target" fullword ascii
        $s3 = "%s [host] [port]" fullword ascii
        $s4 = "ws2_32.dll is out of date." fullword ascii
        $s5 = "read a strange or incomplete length value" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 200KB and ( 3 of ($s*) ) ) or ( all of them )
}
