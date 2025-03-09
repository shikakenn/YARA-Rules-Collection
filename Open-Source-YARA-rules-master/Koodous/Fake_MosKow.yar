/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/


//41dce59ace9cce668e893c9d2c35d6859dc1c86d631a0567bfde7d34dd5cae0b
//61f7909512c5caf6dd125659428cf764631d5a52c59c6b50112af4a02047774c
//2c89d0d37257c90311436115c1cf06295c39cd0a8c117730e07be029bd8121a0
rule moscow_fake : banker
{
    meta:
        id = "20TkBJeV1SivImmSgJsuTv"
        fingerprint = "v1_sha256_3db649a6d29bfd9e588fec4ab4648139c2d69917acd41b2a4d3aece065c15b60"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Fernando Denis"
        description = "Moskow Droid Development"
        category = "INFO"
        reference = "https://koodous.com/ https://twitter.com/fdrg21"
        thread_level = 3
        in_the_wild = true

    strings:
        $string_a = "%ioperator%"
        $string_b = "%imodel%"
        $string_c = "%ideviceid%"
        $string_d = "%ipackname%"
        $string_e = "VILLLLLL"

    condition:
        all of ($string_*)
}
