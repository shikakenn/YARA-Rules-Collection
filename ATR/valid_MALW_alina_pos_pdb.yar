rule Alina_POS_PDB {

    meta:
        id = "2EB67TqzPx8Ykk8OJKuABK"
        fingerprint = "v1_sha256_9bb8260e3a47567e2460dd474fb74e57987e3d79eb30cdbc2a45b88a16ba1ca2"
        version = "1.0"
        date = "2013-08-08"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Alina POS"
        category = "INFO"
        reference = "https://www.pandasecurity.com/mediacenter/pandalabs/alina-pos-malware/"
        hash = "28b0c52c0630c15adcc857d0957b3b8002a4aeda3c7ec40049014ce33c7f67c3"
        rule_version = "v1"
        malware_family = "Pos:W32/Alina"
        actor_group = "Unknown"

     strings:

         $pdb = "\\Users\\dice\\Desktop\\SRC_adobe\\src\\grab\\Release\\Alina.pdb"

     condition:

         uint16(0) == 0x5a4d and
         filesize < 100KB and
         any of them
}
