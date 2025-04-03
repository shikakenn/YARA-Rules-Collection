rule Windows_Ransomware_Helloxd_0c50f01b {
    meta:
        id = "1uDWSs5t64myn2H4HJBIrz"
        fingerprint = "v1_sha256_71e09fa1a00fa6f3688129ee2b2a8957b84f64ef51fcba5123a6a9df80a9c7e1"
        version = "1.0"
        date = "2022-06-14"
        modified = "2022-07-18"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Elastic Security"
        description = "NA"
        category = "INFO"
        threat_name = "Windows.Ransomware.Helloxd"
        reference_sample = "435781ab608ff908123d9f4758132fa45d459956755d27027a52b8c9e61f9589"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"

    strings:
        $mutex = "With best wishes And good intentions..."
        $ransomnote0 = ":: our TOX below >:)"
        $ransomnote1 = "You can download TOX here"
        $ransomnote2 = "...!XD ::"
        $productname = "HelloXD" ascii wide
        $legalcopyright = "uKn0w" ascii wide
        $description = "VhlamAV" ascii wide
        $companyname = "MicloZ0ft" ascii wide
    condition:
        ($mutex and all of ($ransomnote*)) or (3 of ($productname, $legalcopyright, $description, $companyname))
}

