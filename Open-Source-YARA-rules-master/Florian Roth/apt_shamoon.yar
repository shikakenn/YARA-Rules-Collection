rule CrowdStrike_Shamoon_DroppedFile { 
    meta:
        id = "5fIdHcNelEYVicGrp4uV2I"
        fingerprint = "v1_sha256_ed550832b217f7edceea2edf7c4453925ed1759d97db7728f7face6ff10ee361"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "Rule to detect Shamoon malware http://goo.gl/QTxohN"
        category = "INFO"
        reference = "http://www.rsaconference.com/writable/presentations/file_upload/exp-w01-hacking-exposed-day-of-destruction.pdf"

    strings:
        $testn123 = "test123" wide
        $testn456 = "test456" wide
        $testn789 = "test789" wide
        $testdomain = "testdomain.com" wide $pingcmd = "ping -n 30 127.0.0.1 >nul" wide
    condition:
        (any of ($testn*) or $pingcmd) and $testdomain
}
