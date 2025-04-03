import "pe"
rule sidewinder_apt_rtf_cve_2017_0199{
    meta:
        id = "3Xr6PWZIwcbzM5DzFBbIqg"
        fingerprint = "v1_sha256_63c7b8c251a906ea9ea81a7ea838506cd2c0304b4d197eaff8cd3bac99f860ac"
        version = "1.0"
        date = "2021-09-09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Cluster25"
        description = "NA"
        category = "INFO"
        report = "HTTPS://21649046.FS1.HUBSPOTUSERCONTENT-NA1.NET/HUBFS/21649046/A_RATTLESNAKE_IN_THE_NAVY.PDF"
        hash1 = "282367417cdc711fbad33eb6988c172c61a9a57d9f926addaefabc36cac3c004"
        hash2 = "6d021166bdde0eab22fd4a9f398fdd8ccf8b977ff33a77c518f8d16e56d3eeee"

strings:
$head = "{\\rtf1" ascii
$obj = "objdata 0105000002000000" ascii
$expl = "6D007300680074006D006C000000FFD7E8130000006E756E48544D4C4170706C69636174696F6E" ascii
$s1 = "416374697665584F626A656374" ascii nocase
$s2 = "5176524d384b4e4734504332565a55753765497764426f72686974366761416259796d356c4563306a4453576e585431334a7173467870484f666b7a4c392b2f3d" ascii nocase
$s3 = "62203e3e2031362026203235352c2062203e3e20382026203235352c2062202620323535" ascii nocase
condition:
$head at 0 and $obj and $expl and 2 of ($s*)
}
