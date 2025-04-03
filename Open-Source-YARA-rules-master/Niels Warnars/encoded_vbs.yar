rule encoded_vbs
{
    meta:
        id = "pwT31XdBllC18HeNpEavu"
        fingerprint = "v1_sha256_ee54196696bd68bb3154ac3743d30ff64f2fdb15097eab847fb017b295339fa2"
        version = "1.0"
        date = "2016/07/31"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Niels Warnars"
        description = "Encoded .vbs detection"
        category = "INFO"
        reference = "https://gallery.technet.microsoft.com/Encode-and-Decode-a-VB-a480d74c"

    strings:
        $begin_tag1 = "#@~^" 
        $begin_tag2 = "=="
        $end_tag = "==^#~@"
    condition:
       $begin_tag1 at 0 and $begin_tag2 at 10 and $end_tag
}
