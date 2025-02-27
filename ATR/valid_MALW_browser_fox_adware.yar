rule malw_browser_fox_adware {
     
    meta:
        id = "7Caizhjea2rammeTmfhrk4"
        fingerprint = "v1_sha256_462a05de46ec0d710cac80a05d4935279a43f49cbd5ef49c072f277982a76fce"
        version = "1.0"
        date = "2015-01-15"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Browser Fox Adware based on the PDB reference"
        category = "INFO"
        reference = "https://www.sophos.com/en-us/threat-center/threat-analyses/adware-and-puas/Browse%20Fox.aspx"
        hash = "c6f3d6024339940896dd18f32064c0773d51f0261ecbee8b0534fdd9a149ac64"
        rule_version = "v1"
        malware_family = "Adware:W32/BrowserFox"
        actor_group = "Unknown"

     strings:

         $pdb = "\\Utilities\\130ijkfv.o4g\\Desktop\\Desktop.OptChecker\\bin\\Release\\ BooZaka.Opt"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 800KB and
         any of them
}
