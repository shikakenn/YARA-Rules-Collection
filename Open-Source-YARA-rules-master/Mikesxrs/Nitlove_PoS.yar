rule Nitlove_PoS
{
    meta:
        id = "2iOjfGaWfEqkBQr8L58SD6"
        fingerprint = "v1_sha256_0a4436e77c5cc56326792401e530d00453fa8a1725c4527f838eff237aa198fb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Author = "@X0RC1SM"
        Description = "Looking for uniques strings from reports"
        Reference1 = "https://www.fireeye.com/blog/threat-research/2015/05/nitlovepos_another.html"
        Reference2 = "https://securingtomorrow.mcafee.com/mcafee-labs/evoltin-pos-malware-attacks-via-macro/"
        Date = "2017-10-28"

    strings:
        $STR1 = "nit_love"
          $STR2 = "derpos/gateway.php"
    condition:
        any of them
}
