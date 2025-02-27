rule chikdos_malware_pdb
{
    meta:
        id = "Pia6AmLarGqFGJ2dMi5OX"
        fingerprint = "v1_sha256_150bf809a61aad00df0c49fb6a609b909c84ffb9ca442e143a6c5bf3dfc39314"
        version = "1.0"
        date = "2013-12-02"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Chikdos PDB"
        category = "INFO"
        reference = "http://hackermedicine.com/tag/trojan-chickdos/"
        hash = "c2a0e9f8e880ac22098d550a74940b1d81bc9fda06cebcf67f74782e55e9d9cc"
        rule_version = "v1"
        malware_family = "Dos:W32/ChickDos"
        actor_group = "Unknown"

     strings:

         $pdb = "\\IntergrateCHK\\Release\\IntergrateCHK.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 600KB and
         any of them
}
