rule downloader_darkmegi_pdb {

    meta:
        id = "7euqmFwREi0V5OWDgN2eGf"
        fingerprint = "v1_sha256_47faf8c5296e651f82726a6e8a7843dfa0f98e7be7257d2c03efcff550f52140"
        version = "1.0"
        date = "2013-03-06"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect DarkMegi downloader based on PDB"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkmegi"
        hash = "bf849b1e8f170142176d2a3b4f0f34b40c16d0870833569824809b5c65b99fc1"
        rule_version = "v1"
        malware_family = "Downloader:W32/DarkMegi"
        actor_group = "Unknown"

     strings:

         $pdb = "\\RKTDOW~1\\RKTDRI~1\\RKTDRI~1\\objchk\\i386\\RktDriver.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize > 20000KB and
         any of them
}
