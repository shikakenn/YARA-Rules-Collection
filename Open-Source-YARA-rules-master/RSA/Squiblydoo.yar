rule RSA_IR_Windows_COM_bypass_script
{
    meta:
        id = "4jVm3LJPeL4R6VZGvwzG8L"
        fingerprint = "v1_sha256_5a11cfa53d0dd91fcf6b68ec03232b09238cb4d29ca9e236b84be69943a7f0c9"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "RSA IR"
        description = "NA"
        category = "INFO"
        reference = "https://community.rsa.com/community/products/netwitness/blog/2016/04/26/detection-of-com-whitelist-bypassing-with-ecat"
        Date = "22 Apr 2016"
        comment1 = "Detects potential scripts used by COM+ Whitelist Bypass"
        comment2 = "More information on bypass located at: http://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html"

    strings:
        $s1 = "<scriptlet>" nocase
        $s2 = "<registration" nocase
        $s3 = "classid=" nocase
        $s4 = "[CDATA[" nocase
        $s5 = "</script>" nocase
        $s6 = "</registration>" nocase
        $s7 = "</scriptlet>" nocase
 
    condition:
        all of ($s*)
}
