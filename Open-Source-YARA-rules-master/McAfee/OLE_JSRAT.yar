rule APT_OLE_JSRat
{
    meta:
        id = "31gDP5gbDfS9oqL5nVeEFW"
        fingerprint = "v1_sha256_6538b143d7d047bdebaa9f79d66332f77d932b232525b78776396614e6530044"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Rahul Mohandas"
        description = "NA"
        category = "INFO"
        reference = "https://securingtomorrow.mcafee.com/mcafee-labs/stealthy-cyberespionage-campaign-attacks-with-social-engineering"
        Date = "2015-06-16"
        Description = "Targeted attack using Excel/word documents"

strings:
$header = {D0 CF 11 E0 A1 B1 1A E1}
$key1 = "AAAAAAAAAA"
$key2 = "Base64Str" nocase
$key3 = "DeleteFile" nocase
$key4 = "Scripting.FileSystemObject" nocase

condition:
$header at 0 and (all of ($key*) )
}
