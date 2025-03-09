/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-02-17
    Identifier: Locky
*/

rule Locky_Ransomware {
    meta:
        id = "1WGAhUdLXkH5Ht0BmDOnIw"
        fingerprint = "v1_sha256_c7584ea39c4aceedeb0ea2952be6ff212461674175855274f1783eef80ffba86"
        version = "1.0"
        date = "2016-02-17"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth (with the help of binar.ly)"
        description = "Detects Locky Ransomware (matches also on Win32/Kuluoz)"
        category = "INFO"
        reference = "https://goo.gl/qScSrE"
        hash = "5e945c1d27c9ad77a2b63ae10af46aee7d29a6a43605a9bfbf35cebbcff184d8"

    strings:
        $o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } // address=0x4144a7
        $o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } // address=0x413863
    condition:
        all of ($o*)
}
