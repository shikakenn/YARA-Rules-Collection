rule nspss_executable_strings {

    meta:
        id = "1qfO749LKTAGVYYFOxNJhd"
        fingerprint = "v1_sha256_99f8dc2583371d3f57fb675c8f1d7619f524612139307b2a040d6d318405d9e5"
        version = "1.0.0"
        date = "20200320"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "IronNet Threat Research"
        description = "ASCII strings seen in nspps RAT"
        category = "INFO"
        report = "HTTPS://WWW.IRONNET.COM/BLOG/MALWARE-ANALYSIS-NSPPS-A-GO-RAT-BACKDOOR"
        reference = "SHA1:3bbb58a2803c27bb5de47ac33c6f13a9b8a5fd79"

strings:
        $s00 = "%s.lock" wide ascii
        $s01 = ", pass " wide ascii
        $s02 = ", user " wide ascii
        $s03 = "/getT" wide ascii
        $s04 = "/tmp/." wide ascii
        $s05 = "/var/tmp/." wide ascii
        $s06 = "Get task error" wide ascii
        $s07 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36" wide ascii
        $s08 = "SKL=" wide ascii
        $s09 = "Targets for task %d is empty" wide ascii
        $s10 = "Targets getted, type cidr, size %d" wide ascii
        $s11 = "Targets getted, type ip, size %d" wide ascii
        $s12 = "Targets getted, type url, size %d" wide ascii
        $s13 = "Task %d, executed in %s" wide ascii
        $s14 = "Task %d, new targets setted, size %d" wide ascii
        $s15 = "Task %d, processed %d/%d, left %d, thread %d, pps %d" wide ascii
        $s16 = "Try to get targets for %d, offset %d" wide ascii
        $s17 = "UpdateCommand: downloaded to %s" wide ascii
        $s18 = "User-Agent:" wide ascii
        $s19 = "curl" wide ascii
        $s20 = "doTask with type %s"
        $s21 = "exec_out" wide ascii
        $s22 = "firewire.sh" wide ascii
        $s23 = "get md5 of file error" wide ascii
        $s24 = "invalid md5, actual %s, expected %s, url %s" wide ascii
        $s25 = "libpcap-dev" wide ascii
        $s26 = "masscan chmod output %s" wide ascii
        $s27 = "sendSocks %s" wide ascii
        $s28 = "socks port = " wide ascii
        $s29 = "startCmd %s, pid %d" wide ascii
        $s30 = "try to send %d results for task %d"
        $s31 = "versionAndHash is empty" wide ascii
        $s32 = "wget" wide ascii
        $s33 = "Client sent AUTH, but no password is set" wide ascii
condition:
        24 of them
}
