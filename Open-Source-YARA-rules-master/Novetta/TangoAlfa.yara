rule TangoAlfa
{
    meta:
        id = "jMBtgeXOnNJzOPNBmLz8C"
        fingerprint = "v1_sha256_d1f82797a80d91c7894513c92d02ecfe13330037d3b05f3663dccfa52f72139d"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
        description = "NA"
        category = "INFO"
        copyright = "2015 Novetta Solutions"

    strings:
        // $firewall is a shared code string
        $firewall = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""
        
        $testStatus1 = "*****[Start Test -> %s:%d]" wide
        $testStatus2 = "*****[Relay Connect " wide
        $testStatus3 = "*****[Listen Port %d] - " wide
        $testStatus4 = "*****[Error Socket]" wide
        $testStatus5 = "*****[End Test]" wide

    condition:
        2 of them
}
