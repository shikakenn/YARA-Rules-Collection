/*
Yara Rule Set
Author: SECUINFRA Falcon Team
Date: 2022-06-23
Identifier: 0x03-yara_win-Bitter_T-APT-17
Reference: "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
*/

/* Rule Set —————————————————————– */
rule APT_Bitter_PDB_Paths {

    meta:
        id = "1RSgVXAOiwwmnxcn2ZOSiF"
        fingerprint = "v1_sha256_7eb9e4c1b4e0cca070596f3702045756eb32716481bb59f2f8322221804291f5"
        version = "1.0"
        date = "2022-06-22"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        description = "Detects Bitter (T-APT-17) PDB Paths"
        category = "INFO"
        reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        tlp = "WHITE"
        hash0 = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

strings:
// Almond RAT
$pdbPath0 = "C:\\Users\\Window 10 C\\Desktop\\COMPLETED WORK\\" ascii
$pdbPath1 = "stdrcl\\stdrcl\\obj\\Release\\stdrcl.pdb"

// found by Qi Anxin Threat Intellingence Center
// reference: https://mp.weixin.qq.com/s/8j_rHA7gdMxY1_X8alj8Zg
$pdbPath2 = "g:\\Projects\\cn_stinker_34318\\"
$pdbPath3 = "renewedstink\\renewedstink\\obj\\Release\\stimulies.pdb"

condition:
uint16(0) == 0x5a4d
and any of ($pdbPath*)
}
