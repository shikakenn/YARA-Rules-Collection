rule JRAT
{
    meta:
        id = "3tq3gODLnLqzNP6Io1GuSW"
        fingerprint = "v1_sha256_d960e6e96a5099c6c325393b2a3d4081b3de0e726392686ef6a8626b95d5623e"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "@X0RC1SM"
        Description = "Looking for unique PDB"
        Reference = "https://repo.cryptam.com/nodes/03e36f49d38082bcac91716747f7827286fbebee62d412fb39a45b4ec7a082f5.txt"
        Date = "2017-04-05"

    strings:
          $JRAT1 = "/Jrat.classPK" ascii wide nocase
        $JRAT2 = "/JRat.class" ascii wide nocase
            $JRAT3 = "META-INF/MANIFEST.MF" ascii wide nocase
    condition:
        all of them
}
