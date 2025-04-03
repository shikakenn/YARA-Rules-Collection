rule Punkey
{
    meta:
        id = "6CbIqkHxgoFMd8ApYuxM2y"
        fingerprint = "v1_sha256_ed1861eaca855df84111dcc0029fefbf359e4e3ba2ec622089f38837595ed678"
        version = "1.0"
        date = "2015-04-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Trustwave SpiderLabs"
        description = "Used to detect Punkey malware.  Blog: https://www.trustwave.com/Resources/SpiderLabs-Blog/New-POS-Malware-Emerges---Punkey/"
        category = "INFO"

  strings:
    $pdb1 = "C:\\Documents and Settings\\Administrator\\Desktop\\Verios\\jusched\\jusched32.pdb" nocase
    $pdb2 = "C:\\Documents and Settings\\Administrator\\Desktop\\Verios\\jusched\\troi.pdb" nocase
    $pdb3 = "D:\\freelancer\\gale.kreeb\\jusched10-19\\jusched32.pdb" nocase
    $pdb4 = "D:\\freelancer\\gale.kreeb\\jusched10-19\\troi.pdb" nocase
    $pdb5 = "C:\\Users\\iptables\\Desktop\\x86\\jusched32.pdb" nocase
    $pdb6 = "C:\\Users\\iptables\\Desktop\\x86\\troi.pdb"
    $pdb7 = "C:\\Users\\iptables\\Desktop\\27 Octomber\\jusched10-27\\troi.pdb" nocase
    $pdb8 = "D:\\work\\visualstudio\\jusched\\dllx64.pdb" nocase
    $string0 = "explorer.exe" nocase
    $string1 = "jusched.exe" nocase
    $string2 = "dllx64.dll" nocase
    $string3 = "exportDataApi" nocase
    $memory1 = "troi.exe"
    $memory2 = "unkey="
    $memory3 = "key="
    $memory4 = "UPDATE"
    $memory5 = "RUN"
    $memory6 = "SCANNING"
    $memory7 = "86afc43868fea6abd40fbf6d5ed50905"
    $memory8 = "f4150d4a1ac5708c29e437749045a39a"

  condition:
    (any of ($pdb*)) or (all of ($str*)) or (all of ($mem*))
}
