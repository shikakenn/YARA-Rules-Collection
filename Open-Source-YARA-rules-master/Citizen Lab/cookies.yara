private rule CookiesStrings : Cookies Family
{
    meta:
        id = "1C67goQMiVQ3xTAo2WGLpK"
        fingerprint = "v1_sha256_22baeaf0f8f45e4e53c987862a4f3f194721ccdec0111f28dba2aceb99e6296a"
        version = "1.0"
        modified = "2014-06-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Cookies Identifying Strings"
        category = "INFO"

    strings:
        $zip1 = "ntdll.exePK"
        $zip2 = "AcroRd32.exePK"
        $zip3 = "Setup=ntdll.exe\x0d\x0aSilent=1\x0d\x0a"
        $zip4 = "Setup=%temp%\\AcroRd32.exe\x0d\x0a"
        $exe1 = "Leave GetCommand!"
        $exe2 = "perform exe success!"
        $exe3 = "perform exe failure!"
        $exe4 = "Entry SendCommandReq!"
        $exe5 = "Reqfile not exist!"
        $exe6 = "LeaveDealUpfile!"
        $exe7 = "Entry PostData!"
        $exe8 = "Leave PostFile!"
        $exe9 = "Entry PostFile!"
        $exe10 = "\\unknow.zip" wide ascii
        $exe11 = "the url no respon!"
        
    condition:
      (2 of ($zip*)) or (2 of ($exe*))
}

rule Cookies : Family
{
    meta:
        id = "7XoqGMxsk7r3aVUPA9C3eR"
        fingerprint = "v1_sha256_d259acef5ddb942a8db738f307b6497e55ddfeaf0f53b9b418fdcbe1acb27190"
        version = "1.0"
        modified = "2014-06-20"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Cookies"
        category = "INFO"

    condition:
        CookiesStrings
}
