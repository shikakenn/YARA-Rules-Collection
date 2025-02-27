rule malw_mangzamel_trojan
{
    meta:
        id = "7PiQphfKrWctHfSbtusr39"
        fingerprint = "v1_sha256_bab103c671445e0ea916fae290689d30d45021bdca58a495ebd3d6ca9ca55051"
        version = "1.0"
        date = "2014-06-25"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Mangzamel  trojan based on PDB"
        category = "INFO"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mangzamel"
        hash = "4324580ea162a636b7db1efb3a3ba38ce772b7168b4eb3a149df880a47bd72b7"
        rule_version = "v1"
        malware_family = "Trojan:W32/Mangzamel"
        actor_group = "Unknown"

     strings:

         $pdb = "\\svn\\sys\\binary\\i386\\agony.pdb"
         $pdb1 = "\\Windows\\i386\\ndisdrv.pdb"

    condition:
        
        uint16(0) == 0x5a4d and
         filesize < 360KB and
         any of them
}
