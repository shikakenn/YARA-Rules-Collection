rule APT_APT40_Implant_June2020 {
    meta:
        id = "1qlCbrPr7FypVORDQdd160"
        fingerprint = "v1_sha256_47e8b85202a01f97642ec1df9f2e3ec1b4c7afcffc2086a51fb34ac9392fbef1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "APT40 second stage implant"
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/advanced-techniques-used-in-malaysian-focused-apt-campaign"
        date_added = "2020-06-19"

    strings:
        $a = "/list_direction" fullword wide
        $b = "/post_document" fullword wide
        $c = "/postlogin" fullword wide
        $d = "Download Read Path Failed %s" fullword ascii
        $e = "Open Pipe Failed %s" fullword ascii
        $f = "Open Remote File %s Failed For: %s" fullword ascii
        $g = "Download Read Path Failed %s" fullword ascii
        $h = "\\cmd.exe" fullword wide
    condition:
        all of them
}
