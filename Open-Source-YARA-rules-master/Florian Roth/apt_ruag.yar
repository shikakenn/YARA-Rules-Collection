/*
  Yara Rule Set
  Author: Florian Roth
  Date: 2016-05-23
  Identifier: Swiss RUAG APT Case
  Reference: https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case 
*/

rule RUAG_Tavdig_Malformed_Executable {
    meta:
        id = "4veSRojHLO3tOVtBncfVla"
        fingerprint = "v1_sha256_2a6eb90cc77f4556da0b5b0211bf0c4759dae0d78e9c6b765eff0e9a34f52e0f"
        version = "1.0"
        score = 60
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects an embedded executable with a malformed header - known from Tavdig malware"
        category = "INFO"
        reference = "https://goo.gl/N5MEj0"

  condition:
    uint16(0) == 0x5a4d and /* MZ Header */
    uint32(uint32(0x3C)) == 0x0000AD0B /* malformed PE header > 0x0bad */
}

rule RUAG_Bot_Config_File {
    meta:
        id = "2YR6zy8529eJIc8L57yjzA"
        fingerprint = "v1_sha256_0dbf946803214558ec4750191a209315ea22fe0ec7d2d4e908b627c002171ef6"
        version = "1.0"
        score = 60
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a specific config file used by malware in RUAG APT case"
        category = "INFO"
        reference = "https://goo.gl/N5MEj0"

  strings:
    $s1 = "[CONFIG]" ascii
    $s2 = "name = " ascii
    $s3 = "exe = cmd.exe" ascii
  condition:
    $s1 at 0 and $s2 and $s3 and filesize < 160 
}

rule RUAG_Cobra_Malware {
    meta:
        id = "64orWCPPCcvBapZt8szIdo"
        fingerprint = "v1_sha256_5576e8e465eb289e8da44009cb2237080c5b5c3eb6d7a337634d91c5d68ecd80"
        version = "1.0"
        score = 60
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a malware mentioned in the RUAG Case called Carbon/Cobra"
        category = "INFO"
        reference = "https://goo.gl/N5MEj0"

  strings:
    $s1 = "\\Cobra\\Release\\Cobra.pdb" ascii
  condition:
    uint16(0) == 0x5a4d and $s1
}

rule RUAG_Cobra_Config_File {
    meta:
        id = "2ZabtT6xFzUjofANDlnE5T"
        fingerprint = "v1_sha256_98ae475ca2c287589a2a97d592c01cac75013cd9148fa9b350330c078c93d8fd"
        version = "1.0"
        score = 60
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a config text file used by malware Cobra in RUAG case"
        category = "INFO"
        reference = "https://goo.gl/N5MEj0"

  strings:
    $h1 = "[NAME]" ascii

    $s1 = "object_id=" ascii
    $s2 = "[TIME]" ascii fullword
    $s3 = "lastconnect" ascii 
    $s4 = "[CW_LOCAL]" ascii fullword
    $s5 = "system_pipe" ascii
    $s6 = "user_pipe" ascii
    $s7 = "[TRANSPORT]" ascii
    $s8 = "run_task_system" ascii
    $s9 = "[WORKDATA]" ascii 
    $s10 = "address1" ascii
  condition:
    $h1 at 0 and 8 of ($s*) and filesize < 5KB
}

rule RUAG_Exfil_Config_File {
    meta:
        id = "1OMzwD9aJ2qMjQX0TtmeZK"
        fingerprint = "v1_sha256_4183def9c36d2bff37434ca41385005bdaff1c07a3819ee9b0ca6f764f50a230"
        version = "1.0"
        score = 60
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Florian Roth"
        description = "Detects a config text file used in data exfiltration in RUAG case"
        category = "INFO"
        reference = "https://goo.gl/N5MEj0"

  strings:
    $h1 = "[TRANSPORT]" ascii

    $s1 = "system_pipe" ascii
    $s2 = "spstatus" ascii
    $s3 = "adaptable" ascii 
    $s4 = "post_frag" ascii
    $s5 = "pfsgrowperiod" ascii
  condition:
    $h1 at 0 and all of ($s*) and filesize < 1KB
}
