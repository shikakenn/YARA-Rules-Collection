rule nspps_RC4_Key {
    meta:
        id = "1k9Ih0lS5DJQECQkIX0gBw"
        fingerprint = "v1_sha256_451a10771438f48f9bff86f3fd2e30234be9b1722e45c371e16cdffd08dc1f37"
        version = "1.0.0"
        date = "20200320"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "IronNet Threat Research"
        description = "RC4 Key used in nspps RAT"
        category = "INFO"
        report = "HTTPS://WWW.IRONNET.COM/BLOG/MALWARE-ANALYSIS-NSPPS-A-GO-RAT-BACKDOOR"
        reference = "SHA1:3bbb58a2803c27bb5de47ac33c6f13a9b8a5fd79"

    strings:
        $s1 = { 37 36 34 31 35 33 34 34 36 62 36 31 }
    condition:
        all of them
}
