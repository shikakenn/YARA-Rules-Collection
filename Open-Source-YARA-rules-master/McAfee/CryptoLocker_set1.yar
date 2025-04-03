rule CryptoLocker_set1
{
    meta:
        id = "dHv2zOQ0fCjz0U87eWtCs"
        fingerprint = "v1_sha256_bcf1f6e6d990ef92b809324ef7b575f23f2f039308216d4339e8bda6492b52da"
        version = "1.0"
        date = "2014-04-13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Christiaan Beek, Christiaan_Beek@McAfee.com"
        description = "Detection of Cryptolocker Samples"
        category = "INFO"

strings:
    $string0 = "static"
    $string1 = " kscdS"
    $string2 = "Romantic"
    $string3 = "CompanyName" wide
    $string4 = "ProductVersion" wide
    $string5 = "9%9R9f9q9"
    $string6 = "IDR_VERSION1" wide
    $string7 = "  </trustInfo>"
    $string8 = "LookFor" wide
    $string9 = ":n;t;y;"
    $string10 = "        <requestedExecutionLevel level"
    $string11 = "VS_VERSION_INFO" wide
    $string12 = "2.0.1.0" wide
    $string13 = "<assembly xmlns"
    $string14 = "  <trustInfo xmlns"
    $string15 = "srtWd@@"
    $string16 = "515]5z5"
    $string17 = "C:\\lZbvnoVe.exe" wide
condition:
    8 of ($string*)
}
