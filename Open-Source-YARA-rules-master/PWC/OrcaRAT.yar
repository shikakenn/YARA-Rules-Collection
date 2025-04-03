rule OrcaRAT
  {
    meta:
        id = "42NvfC2FaOK3AJzMRT90Gu"
        fingerprint = "v1_sha256_dc7f4ff997950858cc41df97492b275afba5a23edac4bef5be1aad68fd0716f2"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "PwC Cyber Threat Operations   :: @tlansec"
        description = "NA"
        category = "INFO"
        distribution = "TLP WHITE"
        sha1 = "253a704acd7952677c70e0c2d787791b8359efe2c92a5e77acea028393a85613"

  strings:

       $MZ="MZ"

       $apptype1="application/x-ms-application"

       $apptype2="application/x-ms-xbap"

       $apptype3="application/vnd.ms-xpsdocument"

       $apptype4="application/xaml+xml"

       $apptype5="application/x-shockwave-flash"

       $apptype6="image/pjpeg"

       $err1="Set return time error =   %d!"

       $err2="Set return time   success!"

       $err3="Quit success!"

 

condition:

       $MZ at 0 and filesize < 500KB and   (all of ($apptype*) and 1 of ($err*))
  }
