rule Tendrit_2014 : OnePHP

{

    meta:
        id = "3oOZmacMbnauBzEfZ9Qcrz"
        fingerprint = "v1_sha256_e8993a742f9681944f7b0692756a75c74aa96561697d1edc9a8222aefa1673bb"
        version = "1.0"
        date = "2014-12"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        author = "PwC Cyber Threat Operations   :: @tlansec"
        description = "NA"
        category = "INFO"
        hash = "7b83a7cc1afae7d8b09483e36bc8dfbb"
        ref = "[http://pwc.blogs.com/cyber_security_updates/2014/12/festive-spearphishing-merry-christmas-from-an-apt-actor.html]"

strings:

       $url1="favicon"

       $url2="policyref"

       $url3="css.ashx"

       $url4="gsh.js"

       $url5="direct"



       $error1="Open HOST_URL error"

       $error2="UEDone"

       $error3="InternetOpen error"

       $error4="Create process fail"

       $error5="cmdshell closed"

       $error6="invalid command"

       $error7="mget over&bingle"

       $error8="mget over&fail"

 condition:

       (all of ($url*) or all of ($error*)) and filesize < 300KB

}
