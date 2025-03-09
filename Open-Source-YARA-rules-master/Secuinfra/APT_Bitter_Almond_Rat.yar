/*
Yara Rule Set
Author: SECUINFRA Falcon Team
Date: 2022-06-23
Identifier: 0x03-yara_win-Bitter_T-APT-17
Reference: "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
*/

/* Rule Set —————————————————————– */

import "pe"
import "dotnet"

rule APT_Bitter_Almond_RAT {

    meta:
        id = "7fR7tUWmgv3YqqbDPcMtbq"
        fingerprint = "v1_sha256_b8d6b95987fe434fc16c87a7bc144f1fe69301a32bb93588df7c2abbfef62d75"
        version = "1.0"
        date = "2022-06-01"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        description = "Detects Bitter (T-APT-17) Almond RAT (.NET)"
        category = "INFO"
        reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        hash = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"
        tlp = "WHITE"

strings:
$function0 = "GetMacid" ascii
$function1 = "StartCommWithServer" ascii
$function2 = "sendingSysInfo" ascii
$dbg0 = "*|END|*" wide
$dbg1 = "FILE>" wide
$dbg2 = "[Command Executed Successfully]" wide

condition:
uint16(0) == 0x5a4d
and dotnet.version == "v4.0.30319"
and filesize > 12KB // Size on Disk/1.5
and filesize < 68KB // Size of Image*1.5
and any of ($function*)
and any of ($dbg*)
}


