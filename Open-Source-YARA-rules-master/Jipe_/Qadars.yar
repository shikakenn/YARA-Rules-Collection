rule qadars : banker
{
    meta:
        id = "T4wq3aPZpuhTNyrshIxyM"
        fingerprint = "v1_sha256_faa176d9b9d14947eaa6445c37bccbf5f55475def58e066d638587fc67cde721"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Qadars - Mobile part. Maybe Perkele."
        category = "INFO"
        filetype = "memory"
        ref1 = "http://www.lexsi-leblog.fr/cert/qadars-nouveau-malware-bancaire-composant-mobile.html"

    strings:
        $cmd1 = "m?D"
        $cmd2 = "m?S"
        $cmd3 = "ALL"
        $cmd4 = "FILTER"
        $cmd5 = "NONE"
        $cmd6 = "KILL"
        $cmd7 = "CANCEL"
        $cmd8 = "SMS"
        $cmd9 = "DIVERT"
        $cmd10 = "MESS"
        $nofilter = "nofilter1111111"
        $botherderphonenumber1 = "+380678409210"

    condition:
        all of ($cmd*) or $nofilter or any of ($botherderphonenumber*)
}
