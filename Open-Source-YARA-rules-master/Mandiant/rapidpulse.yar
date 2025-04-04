rule FE_APT_Webshell_PL_RAPIDPULSE_1
{
    meta:
        id = "UPvEpRQDb8J2BBce419aA"
        fingerprint = "v1_sha256_a2ac67dcb7d137981a82cddb184a3908e6c046deb881a3b2de05302a2c9f0d9b"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Mandiant"
        description = "NA"
        category = "INFO"
        date_created = "2021-05-17"

    strings:
        $r1 = /my[\x09\x20]{1,32}@\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}split[\x09\x20]{0,32}\([\x09\x20]{0,32}\x2f\x2f/
        $r2 = /my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}MIME::Base64::decode_base64[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{0,32}\)[\x09\x20]{0,32};[\S\s]{0,128}my[\x09\x20]{1,32}\$\w{1,64}[\x09\x20]{0,32}=[\x09\x20]{0,32}substr[\x09\x20]{0,32}\([\x09\x20]{0,32}\$\w{1,64}[\x09\x20]{0,32},[\x09\x20]{0,32}\d[\x09\x20]{0,32}\)[\x09\x20]{0,32};[\s\S]{0,64}return[\x09\x20]{1,32}\$/
        $s1 = "use MIME::Base64"
        $s2 = "CGI::param("
        $s3 = "popen"
        $s4 = "print CGI::header()"
        $s5 = "(0..255)"
    condition:
        (all of ($s*)) and (@r1[1] < @r2[1])
}
