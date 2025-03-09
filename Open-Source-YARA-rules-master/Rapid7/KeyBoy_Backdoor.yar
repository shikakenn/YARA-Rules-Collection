rule KeyBoy_Backdoor  
{  
    meta:
        id = "7gpjJsX9I0NIzePI3L9aXO"
        fingerprint = "v1_sha256_c0d32ec7ec4514fe11298de13baedec6fdff1d869f25efaa75aa050f0669da6a"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Rapid7 Labs"
        description = "NA"
        category = "INFO"
        reference = "https://community.rapid7.com/community/infosec/blog/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india"

    strings:  
        $1 = "$login$"  
        $2 = "$sysinfo$"  
        $3 = "$shell$"  
        $4 = "$fileManager$"  
        $5 = "$fileDownload$"  
        $6 = "$fileUpload$"  
  
    condition:  
        all of them  
}  
