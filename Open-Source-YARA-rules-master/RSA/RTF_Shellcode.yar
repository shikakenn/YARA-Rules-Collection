rule RTF_Shellcode
{
    meta:
        id = "290qU4QRHvclkZCGT7WL5L"
        fingerprint = "v1_sha256_a2dbce51c78eda1797e9769f77a0cce20d52987f6993ee8880915039843cf940"
        version = "1.0"
        date = "01/21/13"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "RSA-IR – Jared Greenhill"
        description = "identifies RTF's with potential shellcode"
        category = "INFO"
        reference = "https://community.rsa.com/community/products/netwitness/blog/2014/02/12/triaging-malicious-microsoft-office-documents-cve-2012-0158"
        filetype = "RTF"

strings:
                $rtfmagic={7B 5C 72 74 66}
                $scregex=/[39 30]{2,20}/
 
condition:
                ($rtfmagic at 0) and ($scregex)
}
