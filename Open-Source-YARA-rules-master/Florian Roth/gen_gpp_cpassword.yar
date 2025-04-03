
rule Groups_cpassword {
    meta:
        id = "74WCjTuzv2yG9AMa4wzZtZ"
        fingerprint = "v1_sha256_de37dc77d9a2462f5d54ad5225405c6d95dad39e67a893f5442b26dc641a20f9"
        version = "1.0"
        score = 50
        date = "2015-09-08"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Groups XML contains cpassword value, which is decrypted password - key is in MSDN http://goo.gl/mHrC8P"
        category = "INFO"
        reference = "http://www.grouppolicy.biz/2013/11/why-passwords-in-group-policy-preference-are-very-bad/"

    strings:
        $s1 = / cpassword=\"[^\"]/ ascii
        $s2 = " changeLogon=" ascii
        $s3 = " description=" ascii
        $s4 = " acctDisabled=" ascii
    condition:
        uint32be(0) == 0x3C3F786D  /* <?xm */
        and filesize < 1000KB
        and all of ($s*)  
}

