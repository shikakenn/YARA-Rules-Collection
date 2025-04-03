/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-07-14
    Identifier: SeaDuke
*/

/* Rule Set ----------------------------------------------------------------- */

rule SeaDuke_Sample {
    meta:
        id = "2TCiKUX99Fq8y5UPi7Q9Fw"
        fingerprint = "v1_sha256_5a2a4d911cd42ffaf4bd91089dcf9e534851b5feb659837fc87a342bd5e2ba27"
        version = "1.0"
        score = 70
        date = "2015-07-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "SeaDuke Malware - file 3eb86b7b067c296ef53e4857a74e09f12c2b84b666fc130d1f58aec18bc74b0d"
        category = "INFO"
        reference = "http://goo.gl/MJ0c2M"
        hash = "d2e570129a12a47231a1ecb8176fa88a1bf415c51dabd885c513d98b15f75d4e"

    strings:
        $s0 = "bpython27.dll" fullword ascii
        $s1 = "email.header(" fullword ascii /* PEStudio Blacklist: strings */
        $s2 = "LogonUI.exe" fullword wide /* PEStudio Blacklist: strings */
        $s3 = "Crypto.Cipher.AES(" fullword ascii /* PEStudio Blacklist: strings */
        $s4 = "mod is NULL - %s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}
