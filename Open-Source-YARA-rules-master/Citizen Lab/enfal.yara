private rule EnfalCode : Enfal Family 
{
    meta:
        id = "1HZXiHEiD1iD7P4Y67M1Z6"
        fingerprint = "v1_sha256_aef331683e1392905219c2b378658fd5cb0cdfbafd088c4f10e82542fccbd97c"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Enfal code tricks"
        category = "INFO"

    strings:
        // mov al, 20h; sub al, bl; add [ebx+esi], al; push esi; inc ebx; call edi; cmp ebx, eax
        $decrypt = { B0 20 2A C3 00 04 33 56 43 FF D7 3B D8 }
        
    condition:
        any of them
}

private rule EnfalStrings : Enfal Family
{
    meta:
        id = "3OvRI7OR1MI1ISl0gkQIkv"
        fingerprint = "v1_sha256_2965178332e434177c26f3d73ae9193eaf3ca28c60f0749939b8b9d1877f991a"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Enfal Identifying Strings"
        category = "INFO"

    strings:
        $ = "D:\\work\\\xe6\xba\x90\xe5\x93\xa5\xe5\x85\x8d\xe6\x9d\x80\\tmp\\Release\\ServiceDll.pdb"
        $ = "e:\\programs\\LuridDownLoader"
        $ = "LuridDownloader for Falcon"
        $ = "DllServiceTrojan"
        $ = "\\k\\\xe6\xa1\x8c\xe8\x9d\xa2\\"
        $ = "EtenFalcon\xef\xbc\x88\xe4\xbf\xae\xe6\x94\xb9\xef\xbc\x89"
        $ = "Madonna\x00Jesus"
        $ = "/iupw82/netstate"
        $ = "fuckNodAgain"
        $ = "iloudermao"
        $ = "Crpq2.cgi"
        $ = "Clnpp5.cgi"
        $ = "Dqpq3ll.cgi"
        $ = "dieosn83.cgi"
        $ = "Rwpq1.cgi"
        $ = "/Ccmwhite"
        $ = "/Cmwhite"
        $ = "/Crpwhite"
        $ = "/Dfwhite"
        $ = "/Query.txt"
        $ = "/Ufwhite"
        $ = "/cgl-bin/Clnpp5.cgi"
        $ = "/cgl-bin/Crpq2.cgi"
        $ = "/cgl-bin/Dwpq3ll.cgi"
        $ = "/cgl-bin/Owpq4.cgi"
        $ = "/cgl-bin/Rwpq1.cgi"
        $ = "/trandocs/mm/"
        $ = "/trandocs/netstat"
        $ = "NFal.exe"
        $ = "LINLINVMAN"
        $ = "7NFP4R9W"
        
    condition:
        any of them
}

rule Enfal : Family
{
    meta:
        id = "4MY02M7nN9YTUa2iL6f29X"
        fingerprint = "v1_sha256_45aa94bb890a65158605ead0dd8402131eb1b63adea3a7ff816784c11cd62081"
        version = "1.0"
        modified = "2014-06-19"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Seth Hardy"
        description = "Enfal"
        category = "INFO"

    condition:
        EnfalCode or EnfalStrings
}
