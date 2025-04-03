rule CryptoLocker_rule2
{
    meta:
        id = "3lL6X8qXk56tJMSYQaLcMJ"
        fingerprint = "v1_sha256_571f7cebce3a937a723d9749be9bfbeca43fb0435da3076ca9af984ffeb852da"
        version = "1.0"
        date = "2014-04-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
        description = "Detection of CryptoLocker Variants"
        category = "INFO"

strings:
    $string0 = "2.0.1.7" wide
    $string1 = "    <security>"
    $string2 = "Romantic"
    $string3 = "ProductVersion" wide
    $string4 = "9%9R9f9q9"
    $string5 = "IDR_VERSION1" wide
    $string6 = "button"
    $string7 = "    </security>"
    $string8 = "VFileInfo" wide
    $string9 = "LookFor" wide
    $string10 = "      </requestedPrivileges>"
    $string11 = " uiAccess"
    $string12 = "  <trustInfo xmlns"
    $string13 = "last.inf"
    $string14 = " manifestVersion"
    $string15 = "FFFF04E3" wide
    $string16 = "3,31363H3P3m3u3z3"
condition:
    8 of ($string*)
}
