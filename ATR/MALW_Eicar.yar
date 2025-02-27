rule malw_eicar  {
    
    meta:
        id = "7Yl81KO4gIZshk6jBqrSEl"
        fingerprint = "v1_sha256_564b0592f40582fe71e2dab0c0f25c168462f9297c13e7c9f06ac51b492e4533"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect the EICAR pattern"
        category = "INFO"
        reference = "https://www.eicar.org/"
        hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        rule_version = "v1"
        malware_family = "W32/Eicar"
        actor_group = "Unknown"

    strings:

        $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii

    condition:

         any of them
}
