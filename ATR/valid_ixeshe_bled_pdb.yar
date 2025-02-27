rule ixeshe_bled_malware_pdb {
    meta:
        id = "3putCLs7m93sbEv1tn4zbr"
        fingerprint = "v1_sha256_7d2ce7644e25a56c101c148a32f7b0f7c3185c0c17f4d65eaef257f6ac7f8ffb"
        version = "1.0"
        date = "2012-05-30"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Ixeshe_bled malware based on PDB"
        category = "INFO"
        reference = "https://attack.mitre.org/software/S0015/"
        hash = "d1be51ef9a873de85fb566d157b034234377a4a1f24dfaf670e6b94b29f35482"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Ixeshe"
        actor_group = "Unknown"

     strings:

         $pdb = "\\code\\Blade2009.6.30\\Blade2009.6.30\\EdgeEXE_20003OC\\Debug\\EdgeEXE.pdb"

     condition:

         uint16(0) == 0x5a4d and 
        filesize < 200KB and 
        any of them
}
