/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-05-07
    Identifier: Kraken_Malware
*/

rule Kraken_Bot_Sample {
    meta:
        id = "45XITHRZbr2bqdn2mC6TPL"
        fingerprint = "v1_sha256_2e0f0a981ce3483aad8e48f6a259f9875ea4f8449feb24bafbae07243dd82a16"
        version = "1.0"
        score = 90
        date = "2015-05-07"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Kraken Bot Sample - file inf.bin"
        category = "INFO"
        reference = "https://blog.gdatasoftware.com/blog/article/dissecting-the-kraken.html"
        hash = "798e9f43fc199269a3ec68980eb4d91eb195436d"

    strings:
        $s2 = "%s=?getname" fullword ascii
        $s4 = "&COMPUTER=^" fullword ascii
        $s5 = "xJWFwcGRhdGElAA=" fullword ascii /* base64 encoded string '%appdata%' */
        $s8 = "JVdJTkRJUi" fullword ascii /* base64 encoded string '%WINDIR' */
        $s20 = "btcplug" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

