/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

rule adware : ads
{
    meta:
        id = "5jGaGnM86CX089ef1wgIq4"
        fingerprint = "v1_sha256_4272741e96e23c15a1166096afb70125a11372bb36286b9ad580d3c008d75c47"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Fernando Denis Ramirez https://twitter.com/fdrg21"
        description = "Adware"
        category = "INFO"
        reference = "https://koodous.com/"
        sample = "5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b"

    strings:
        $string_a = "banner_layout"
        $string_b = "activity_adpath_sms"
        $string_c = "adpath_title_one"
        $string_d = "7291-2ec9362bd699d0cd6f53a5ca6cd"

    condition:
        all of ($string_*)
        
}
