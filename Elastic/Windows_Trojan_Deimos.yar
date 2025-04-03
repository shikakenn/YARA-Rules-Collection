rule Windows_Trojan_Deimos_f53aee03 {
    meta:
        id = "4AJgBHeg2WupRnOsHdXmtf"
        fingerprint = "v1_sha256_07675844a8790f8485b6545e7466cdef8ac4f92dec4cd8289aeaad2a0a448691"
        version = "1.0"
        date = "2021-09-18"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/going-coast-to-coast-climbing-the-pyramid-with-the-deimos-implant"
        threat_name = "Windows.Trojan.Deimos"
        reference_sample = "2c1941847f660a99bbc6de16b00e563f70d900f9dbc40c6734871993961d3d3e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = "\\APPDATA\\ROAMING" wide fullword
        $a2 = "{\"action\":\"ping\",\"" wide fullword
        $a3 = "Deimos" ascii fullword
    condition:
        all of ($a*)
}

rule Windows_Trojan_Deimos_c70677b4 {
    meta:
        id = "6ItCk2uRT0L0sNu7OAXyjV"
        fingerprint = "v1_sha256_c969221f025b114b9d5738d43b6021ab9481dbc6b35eb129ea4f806160b1adc3"
        version = "1.0"
        date = "2021-09-18"
        modified = "2022-01-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/going-coast-to-coast-climbing-the-pyramid-with-the-deimos-implant"
        threat_name = "Windows.Trojan.Deimos"
        reference_sample = "2c1941847f660a99bbc6de16b00e563f70d900f9dbc40c6734871993961d3d3e"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $a1 = { 00 57 00 58 00 59 00 5A 00 5F 00 00 17 75 00 73 00 65 00 72 00 }
        $a2 = { 0C 08 16 1F 68 9D 08 17 1F 77 9D 08 18 1F 69 9D 08 19 1F 64 9D }
    condition:
        1 of ($a*)
}

