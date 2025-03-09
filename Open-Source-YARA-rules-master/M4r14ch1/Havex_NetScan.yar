rule Havex_NetScan_Malware {
    meta:
        id = "2Yvoyla1EBIm1RhBwSwHBO"
        fingerprint = "v1_sha256_8bf6b1a42c4a5a41d956b0c67e45a5a3a7717a4d0a7ce57fd55c669c4900b914"
        version = "1.0"
        date = "2015/12/21"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "M4r14ch1"
        description = "This rule will search for known indicators of a Havex Network Scan module infection. This module looks for hosts listening on known ICS-related ports to identify OPC or ICS systems and the file created when the scanning data is written."
        category = "INFO"
        reference = "https://github.com/M4r14ch1/Havex-Network-Scanner-Modules"

        strings:
                $s0 = "~tracedscn.yls" wide nocase //yls file created in temp directory
                $s1 = { 2B E2 ?? }      //Measuresoft ScadaPro
                $s2 = { 30 71 ?? }      //7-Technologies IGSS SCADA
               /* $s3 = { 0A F1 2? }      //Rslinx*/
            
        condition:
                $s0 and ($s1 or $s2 /*or $s3*/)
}

