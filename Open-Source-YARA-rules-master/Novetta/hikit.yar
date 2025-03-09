rule hikit
{
    meta:
        id = "4ap42UQh1HLqFskDWKE7vC"
        fingerprint = "v1_sha256_24cb697327933d445ed94fbdc8e30b67ef9221aafea4e003ba3c34fde8733dbd"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "Novetta"
        Reference = "https://www.novetta.com/wp-content/uploads/2014/11/HiKit.pdf"

    strings:
        $hikit_pdb1 = /(H|h)ikit_/
        $hikit_pdb2 = "hikit\\"
        $hikit_str3 = "hikit>" wide

        $driver = "w7fw.sys" wide
        $device = "\\Device\\w7fw" wide
        $global = "Global\\%s__HIDE__" wide nocase
        $backdr = "backdoor closed" wide
        $hidden = "*****Hidden:" wide

    condition:
        (1 of ($hikit_pdb1,$hikit_pdb2,$hikit_str3)) and ($driver or $device or $global or $backdr or $hidden)
}
