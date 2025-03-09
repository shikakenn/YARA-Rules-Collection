/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-05-05
    Identifier: CarbonGrabber
*/

/* Rule Set ----------------------------------------------------------------- */

rule Rombertik_CarbonGrabber {
    meta:
        id = "3HjfRopR45Bs8YPiwUTm6H"
        fingerprint = "v1_sha256_ddc3ebcc460909a4afc9994cae53c9b7642f92ab6f16e2653f6b2d5002a33cda"
        version = "1.0"
        date = "2015-05-05"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects CarbonGrabber alias Rombertik - file Copy#064046.scr"
        category = "INFO"
        reference = "http://blogs.cisco.com/security/talos/rombertik"
        hash1 = "2f9b26b90311e62662c5946a1ac600d2996d3758"
        hash2 = "aeb94064af2a6107a14fd32f39cb502e704cd0ab"
        hash3 = "c2005c8d1a79da5e02e6a15d00151018658c264c"
        hash4 = "98223d4ec272d3a631498b621618d875dd32161d"

    strings:
        $x1 = "ZwGetWriteWatch" fullword ascii
        $x2 = "OutputDebugStringA" fullword ascii
        $x3 = "malwar" fullword ascii
        $x4 = "sampl" fullword ascii
        $x5 = "viru" fullword ascii
        $x6 = "sandb" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 5MB and all of them
}

rule Rombertik_CarbonGrabber_Panel_InstallScript {
    meta:
        id = "4WbastcovC27in9GKIE6kt"
        fingerprint = "v1_sha256_a0edc53aea21bc317f510a4a463ca677d9dc1ec234ca9824bc46711c851f2ccc"
        version = "1.0"
        date = "2015-05-05"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects CarbonGrabber alias Rombertik panel install script - file install.php"
        category = "INFO"
        reference = "http://blogs.cisco.com/security/talos/rombertik"
        hash = "cd6c152dd1e0689e0bede30a8bd07fef465fbcfa"

    strings:
        $s0 = "$insert = \"INSERT INTO `logs` (`id`, `ip`, `name`, `host`, `post`, `time`, `bro" ascii
        $s3 = "`post` text NOT NULL," fullword ascii
        $s4 = "`host` text NOT NULL," fullword ascii
        $s5 = ") ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;\" ;" fullword ascii
        $s6 = "$db->exec($columns); //or die(print_r($db->errorInfo(), true));;" fullword ascii
        $s9 = "$db->exec($insert);" fullword ascii
        $s10 = "`browser` text NOT NULL," fullword ascii
        $s13 = "`ip` text NOT NULL," fullword ascii
    condition:
        filesize < 3KB and all of them
}

rule Rombertik_CarbonGrabber_Panel {
    meta:
        id = "3cQk9GJCGkNVoThjF1S1wn"
        fingerprint = "v1_sha256_8b7fde3c3894b7aa83e05f6a1b820195276f8738fde218485c0465afaed88427"
        version = "1.0"
        date = "2015-05-05"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects CarbonGrabber alias Rombertik Panel - file index.php"
        category = "INFO"
        reference = "http://blogs.cisco.com/security/talos/rombertik"
        hash = "e6e9e4fc3772ff33bbeeda51f217e9149db60082"

    strings:
        $s0 = "echo '<meta http-equiv=\"refresh\" content=\"0;url=index.php?a=login\">';" fullword ascii
        $s1 = "echo '<meta http-equiv=\"refresh\" content=\"2;url='.$website.'/index.php?a=login" ascii
        $s2 = "header(\"location: $website/index.php?a=login\");" fullword ascii
        $s3 = "$insertLogSQL -> execute(array(':id' => NULL, ':ip' => $ip, ':name' => $name, ':" ascii
        $s16 = "if($_POST['username'] == $username && $_POST['password'] == $password){" fullword ascii
        $s17 = "$SQL = $db -> prepare(\"TRUNCATE TABLE `logs`\");" fullword ascii
    condition:
        filesize < 46KB and all of them
}

rule Rombertik_CarbonGrabber_Builder {
    meta:
        id = "kBeE0PRLTIbon754cVyIj"
        fingerprint = "v1_sha256_e9d13913ee03926920eba33a4dac2a6e9aeaaa54949c5bfea8dd956cf233abae"
        version = "1.0"
        date = "2015-05-05"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects CarbonGrabber alias Rombertik Builder - file Builder.exe"
        category = "INFO"
        reference = "http://blogs.cisco.com/security/talos/rombertik"
        hash = "b50ecc0ba3d6ec19b53efe505d14276e9e71285f"

    strings:
        $s0 = "c:\\users\\iden\\documents\\visual studio 2010\\Projects\\FormGrabberBuilderC++" ascii
        $s1 = "Host(www.panel.com): " fullword ascii
        $s2 = "Path(/form/index.php?a=insert): " fullword ascii
        $s3 = "FileName: " fullword ascii
        $s4 = "~Rich8" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 35KB and all of them
}

rule Rombertik_CarbonGrabber_Builder_Server {
    meta:
        id = "4giDry3ZzBZrjo3hgvJQ8D"
        fingerprint = "v1_sha256_693c92128166c72aded066fa66eef906a9f6027c65b889f3a487a38382f29982"
        version = "1.0"
        date = "2015-05-05"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects CarbonGrabber alias Rombertik Builder Server - file Server.exe"
        category = "INFO"
        reference = "http://blogs.cisco.com/security/talos/rombertik"
        hash = "895fab8d55882eac51d4b27a188aa67205ff0ae5"

    strings:
        $s0 = "C:\\WINDOWS\\system32\\svchost.exe" fullword ascii
        $s3 = "Software\\Microsoft\\Windows\\Currentversion\\RunOnce" fullword ascii
        $s4 = "chrome.exe" fullword ascii
        $s5 = "firefox.exe" fullword ascii
        $s6 = "chrome.dll" fullword ascii
        $s7 = "@KERNEL32.DLL" fullword wide
        $s8 = "Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome" ascii
        $s10 = "&post=" fullword ascii
        $s11 = "&host=" fullword ascii
        $s12 = "Ws2_32.dll" fullword ascii
        $s16 = "&browser=" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and 8 of them
}
