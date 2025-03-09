/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2016-07-19
    Identifier: Invoke-Mimikatz
*/

/* Rule Set ----------------------------------------------------------------- */

rule Invoke_Mimikatz {
    meta:
        id = "2KUpHWuxzQrntqpMkQzj2c"
        fingerprint = "v1_sha256_88b289276c7d570e41b229f1d902c845ae0db51c3b37de05b11aed02fcd2d847"
        version = "1.0"
        date = "2016-08-03"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects Invoke-Mimikatz String"
        category = "INFO"
        reference = "https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz"

    strings:
        $x1 = "Invoke-Mimikatz" wide fullword
    condition:
      1 of them
}
