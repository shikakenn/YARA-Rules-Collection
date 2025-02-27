rule apt_aurora_pdb_samples {
     
    meta:
        id = "6cu5axa8UP55LCiTvdyfT6"
        fingerprint = "v1_sha256_5791ae7b96f2b59d0cca1ab97455bb4745edad8980ac4aff22aa36e0bc4f240e"
        version = "1.0"
        date = "2010-01-11"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Aurora APT Malware 2006-2010"
        category = "INFO"
        reference = "https://en.wikipedia.org/wiki/Operation_Aurora"
        hash = "ce7debbcf1ca3a390083fe5753f231e632017ca041dfa662ad56095a500f2364"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Aurora"
        actor_group = "Unknown"

     strings:

         $pdb = "\\AuroraVNC\\VedioDriver\\Release\\VedioDriver.pdb"
         $pdb1 = "\\Aurora_Src\\AuroraVNC\\Avc\\Release\\AVC.pdb"
     
     condition:
 
         uint16(0) == 0x5a4d and
         filesize < 150KB and
         any of them
}
