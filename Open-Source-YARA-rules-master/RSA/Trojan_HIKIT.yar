rule Trojan_HIKIT
{
    meta:
        id = "6BGqAZbtjsQj6ydn1n8apV"
        fingerprint = "v1_sha256_ad9fbbbb98140bbc710e3715ec58681735a87a5290e82666ac9c42c46d488f14"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "HB"
        Date = "26 Sep 2013"
        Project = "Orion"
        MD5 = "7D4F241428A2496142DF1C4A376CEC88"
        MD5 = "A5F07E00D3EEF7A16ECFEC03E94677E3"
        Reference = "https://blogs.rsa.com/wp-content/uploads/2015/05/RSA-IR-Case-Study.pdf"

    strings:
        $b1 = {63006F006E006E006500630074002000250064002E00250064002E00250064002E002500640020002500640000000000680069006B00690074003E}
        $b2 = {68006900740078002E0073007900730000006D00610074007200690078005F00700061007300730077006F007200}
        $b3 = {700072006F0078007900000063006F006E006E006500630074000000660069006C006500000000007300680065006C006C}
        $a1 = "Open backdoor error" wide
        $a2 = "data send err..." wide

    condition:
        any of ($b*) or all of ($a*)
}
