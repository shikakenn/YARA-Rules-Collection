/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-09-05
    Identifier: Buckeye
*/

/* Rule Set ----------------------------------------------------------------- */

rule Buckeye_Osinfo {
    meta:
        id = "4qUyF5abFe2srRcYWJi3C8"
        fingerprint = "v1_sha256_782ae4293db0839190a9533d2c45baff92527867bfcd048ccae82611f165601b"
        version = "1.0"
        date = "2016-09-05"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects OSinfo tool used by the Buckeye APT group"
        category = "INFO"
        reference = "http://www.symantec.com/connect/blogs/buckeye-cyberespionage-group-shifts-gaze-us-hong-kong"

    strings:
        $s1 = "-s ShareInfo ShareDir" fullword ascii
        $s2 = "-a Local And Global Group User Info" fullword ascii
        $s3 = "-f <infile> //input server list from infile, OneServerOneLine" fullword ascii
        $s4 = "info <\\server> <user>" fullword ascii
        $s5 = "-c Connect Test" fullword ascii
        $s6 = "-gd Group Domain Admins" fullword ascii
        $s7 = "-n NetuseInfo" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 3 of ($s*)
}

rule RemoteCmd {
    meta:
        id = "EiZ3wHSAyjwrbnnvn7Nn"
        fingerprint = "v1_sha256_40f1bb13947e627fec41cc2e8d9153bcab3f48358928794c19e80a3fc7982d29"
        version = "1.0"
        date = "2016-09-08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a remote access tool used by APT groups - file RemoteCmd.exe"
        category = "INFO"
        reference = "http://goo.gl/igxLyF"
        hash1 = "5264d1de687432f8346617ac88ffcb31e025e43fc3da1dad55882b17b44f1f8b"

    strings:
        $s1 = "RemoteCmd.exe" fullword wide
        $s2 = "\\Release\\RemoteCmd.pdb" fullword ascii
        $s3 = "RemoteCmd [ComputerName] [Executable] [Param1] [Param2] ..." fullword wide
        $s4 = "http://{0}:65101/CommandEngine" fullword wide
        $s5 = "Brenner.RemoteCmd.Client" fullword ascii
        $s6 = "$b1888995-1ee5-4f6d-82df-d2ab8ae73d63" fullword ascii
    condition:
        ( uint16(0) == 0x5a4d and filesize < 50KB and 2 of them ) or ( 4 of them )
}

rule ChromePass {
    meta:
        id = "5byK9j5U3T2DNMQWDzDBPn"
        fingerprint = "v1_sha256_10460b4c804ee630e3066d1fc34fa5b1c52a35602cfc7fede949b2769a4eef52"
        version = "1.0"
        date = "2016-09-08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a tool used by APT groups - file ChromePass.exe"
        category = "INFO"
        reference = "http://goo.gl/igxLyF"
        hash1 = "5ff43049ae18d03dcc74f2be4a870c7056f6cfb5eb636734cca225140029de9a"

    strings:
        $x1 = "\\Release\\ChromePass.pdb" fullword ascii
        $x2 = "Windows Protect folder for getting the encryption keys" wide
        $x3 = "Chrome User Data folder where the password file is stored" wide

        $s1 = "Opera Software\\Opera Stable\\Login Data" fullword wide
        $s2 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword wide
        $s3 = "Load the passwords from another Windows user or external drive: " fullword wide
        $s4 = "Chrome Passwords List!Select the windows profile folder" fullword wide
        $s5 = "Load the passwords of the current logged-on user" fullword wide
        $s6 = "Windows Login Password:" fullword wide
        $s7 = "SELECT origin_url, action_url, username_element, username_value, password_element, password_value, signon_realm, date_created fr" ascii
        $s8 = "Chrome Password Recovery" fullword wide
    condition:
        ( uint16(0) == 0x5a4d and filesize < 700KB and 1 of ($x*) ) or ( 5 of them )
}
