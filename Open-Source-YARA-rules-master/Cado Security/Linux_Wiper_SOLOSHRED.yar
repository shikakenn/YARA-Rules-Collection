rule Linux_Wiper_SOLOSHRED {
    meta:
        id = "1pL5THMCMYSWatbKDfooOA"
        fingerprint = "v1_sha256_bc3e574406c635922c278723f6eebd97562123b42b372d2b023fd6f433581e8d"
        version = "1.0"
        date = "2022-04-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mmuir@cadosecurity.com"
        description = "Detects SOLOSHRED wiper used against Ukrainian ICS"
        category = "INFO"
        reference = "https://github.com/cado-security/DFIR_Resources_Industroyer2"
        hash = "87ca2b130a8ec91d0c9c0366b419a0fce3cb6a935523d900918e634564b88028"
        license = "Apache License 2.0"

    strings:
        $a = "printenv | grep -i \"ora\"" ascii
        $b = "shred" ascii
    $c = "--no-preserve-root" ascii
        $d = "/dev/dsk" ascii
    $e = "$(ls /)" ascii
    condition:
        all of them
}
