rule Dridex_Trojan_XML {
    meta:
        id = "7GSUuRIVH5QzkgSoZ5HL3q"
        fingerprint = "v1_sha256_25b6340d782ee20723b2f17f3434a0b27b1561ab22d5a8f859e97e0ac126f651"
        version = "1.0"
        date = "2015/03/08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth @4nc4p"
        description = "Dridex Malware in XML Document"
        category = "INFO"
        reference = "https://threatpost.com/dridex-banking-trojan-spreading-via-macros-in-xml-files/111503"
        hash1 = "88d98e18ed996986d26ce4149ae9b2faee0bc082"
        hash2 = "3b2d59adadf5ff10829bb5c27961b22611676395"
        hash3 = "e528671b1b32b3fa2134a088bfab1ba46b468514"
        hash4 = "981369cd53c022b434ee6d380aa9884459b63350"
        hash5 = "96e1e7383457293a9b8f2c75270b58da0e630bea"

    strings:
        // can be ascii or wide formatted - therefore no restriction
        $c_xml      = "<?xml version="
        $c_word     = "<?mso-application progid=\"Word.Document\"?>"
        $c_macro    = "w:macrosPresent=\"yes\""
        $c_binary   = "<w:binData w:name="
        $c_0_chars  = "<o:Characters>0</o:Characters>"
        $c_1_line   = "<o:Lines>1</o:Lines>"
    condition:
        all of ($c*)
}
