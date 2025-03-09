/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-06-14
    Identifier: Fancy Bear and Cozy Bear Report - CrowdStrike
*/

/* Rule Set ----------------------------------------------------------------- */

rule COZY_FANCY_BEAR_Hunt {
    meta:
        id = "1HRmMvWig6TSsnQrhwgatL"
        fingerprint = "v1_sha256_9009f181eeecce0ae322ba24335426399cf4484dfc9b7ea6905fb163b4bf0a25"
        version = "1.0"
        date = "2016-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Cozy Bear / Fancy Bear C2 Server IPs"
        category = "INFO"
        reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"

    strings:
        $s1 = "185.100.84.134" ascii wide fullword
        $s2 = "58.49.58.58" ascii wide fullword
        $s3 = "218.1.98.203" ascii wide fullword
        $s4 = "187.33.33.8" ascii wide fullword
        $s5 = "185.86.148.227" ascii wide fullword
        $s6 = "45.32.129.185" ascii wide fullword
        $s7 = "23.227.196.217" ascii wide fullword
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule COZY_FANCY_BEAR_pagemgr_Hunt {
    meta:
        id = "3MMBAJBNXjRoSi3APliEpq"
        fingerprint = "v1_sha256_c6055b7cd04b994c80395276e83bec664b7dd32f8093411bfde0850cca39e9f7"
        version = "1.0"
        date = "2016-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
        category = "INFO"
        reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"

    strings:
        $s1 = "pagemgr.exe" wide fullword
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule COZY_FANCY_BEAR_modified_VmUpgradeHelper {
    meta:
        id = "6qwjEeZBZU28KBI5fyOaJV"
        fingerprint = "v1_sha256_5fbb1bb9399ab0d1c3fd99570406627cee3bb46288df988604fc1ff86b07469b"
        version = "1.0"
        date = "2016-06-14"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a malicious VmUpgradeHelper.exe as mentioned in the CrowdStrike report"
        category = "INFO"
        reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"

    strings:
        $s1 = "VMware, Inc." wide fullword
        $s2 = "Virtual hardware upgrade helper service" fullword wide
        $s3 = "vmUpgradeHelper\\vmUpgradeHelper.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and
        filename == "VmUpgradeHelper.exe" and
        not all of ($s*)
}
