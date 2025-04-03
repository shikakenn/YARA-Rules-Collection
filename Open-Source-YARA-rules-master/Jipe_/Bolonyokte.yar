rule Bolonyokte : rat 
{
    meta:
        id = "38wJWX3bLPV166IMdvaF9c"
        fingerprint = "v1_sha256_9ebe036fa6a3e5acf21c0d0e017ff0266bb20eb15432748a98892799c39a6dc4"
        version = "1.0"
        date = "2013-02-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "UnknownDotNet RAT - Bolonyokte"
        category = "INFO"
        filetype = "memory"

    strings:
        $campaign1 = "Bolonyokte" ascii wide
        $campaign2 = "donadoni" ascii wide
        
        $decoy1 = "nyse.com" ascii wide
        $decoy2 = "NYSEArca_Listing_Fees.pdf" ascii wide
        $decoy3 = "bf13-5d45cb40" ascii wide
        
        $artifact1 = "Backup.zip"  ascii wide
        $artifact2 = "updates.txt" ascii wide
        $artifact3 = "vdirs.dat" ascii wide
        $artifact4 = "default.dat"
        $artifact5 = "index.html"
        $artifact6 = "mime.dat"
        
        $func1 = "FtpUrl"
        $func2 = "ScreenCapture"
        $func3 = "CaptureMouse"
        $func4 = "UploadFile"

        $ebanking1 = "Internet Banking" wide
        $ebanking2 = "(Online Banking)|(Online banking)"
        $ebanking3 = "(e-banking)|(e-Banking)" nocase
        $ebanking4 = "login"
        $ebanking5 = "en ligne" wide
        $ebanking6 = "bancaires" wide
        $ebanking7 = "(eBanking)|(Ebanking)" wide
        $ebanking8 = "Anmeldung" wide
        $ebanking9 = "internet banking" nocase wide
        $ebanking10 = "Banking Online" nocase wide
        $ebanking11 = "Web Banking" wide
        $ebanking12 = "Power"

    condition:
        any of ($campaign*) or 2 of ($decoy*) or 2 of ($artifact*) or all of ($func*) or 3 of ($ebanking*)
}
