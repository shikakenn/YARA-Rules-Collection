rule Trojan_Derusbi_AP32_Orion
{
    meta:
        id = "3uNYirndmsE9YUPAid1qzJ"
        fingerprint = "v1_sha256_e140b0eb03eb44173f92360b885278dfc4ca7f6c2266a9477ecfba21db69d130"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "HB"
        Date = "30 Sep 2013"
        Project = "Orion"
        Info = "Compressed with aPACK"
        MagicBytes = "AP32"
        Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

    strings:

        $http1 = {00000000485454502F312E312032303000000000485454502F312E3020323030}
        $http2 = {00000000434F4E4E4543542025733A256420485454502F312E300D0A0D0A0000}
        $file1 = "%s\\seclogon.nls"
        $file2 = "%s\\seclogon.nt"
        $file3 = "%swindows.exe"
        $o1	= "\\wsedrf\\qazxsw"
        $o2 = "\\shell\\open\\command"
        $b1 = {4C4F47494E494E464F3A2025640A0000}
        $b2 = {436F6465506167653A2025730A000000}
        $b3 = {5C636D642E657865}

    condition:
        all of ($http*) or all of ($file*) or all of ($o*) or all of ($b*)

}
