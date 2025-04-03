// Copyright 2020 by FireEye, Inc.
// You may not use this file except in compliance with the license. The license should have been received with this file. You may obtain a copy of the license at:
// https://github.com/fireeye/red_team_tool_countermeasures/blob/master/LICENSE.txt
rule APT_Backdoor_Win_GORAT_5
{
    meta:
        id = "1huQ56mDPAy09IPmQQGdWH"
        fingerprint = "v1_sha256_67f85fb3bedfd18a1226c92318f387be3c7ff9566ca2d554c49cf62389482552"
        version = "1.0"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "NA"
        category = "INFO"
        date_created = "2020-12-02"
        date_modified = "2020-12-02"
        md5 = "cdf58a48757010d9891c62940c439adb, a107850eb20a4bb3cc59dbd6861eaf0f"
        rev = 1

    strings:
        $1 = "comms.BeaconData" fullword
        $2 = "comms.CommandResponse" fullword
        $3 = "rat.BaseChannel" fullword
        $4 = "rat.Config" fullword
        $5 = "rat.Core" fullword
        $6 = "platforms.AgentPlatform" fullword
        $7 = "GetHostID" fullword
        $8 = "/rat/cmd/gorat_shared/dllmain.go" fullword
    condition:
        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550) and all of them
}
