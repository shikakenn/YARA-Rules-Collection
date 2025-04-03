rule TerminatorRat : rat 
{
    meta:
        id = "2vEBHbNpeGJHt6zz71VRlR"
        fingerprint = "v1_sha256_bad656d9b81392a0b7052fcea57d3b603c8e8fb5f94c8632b2bfa2a312f0e819"
        version = "1.0"
        date = "2013-10-24"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Jean-Philippe Teissier / @Jipe_"
        description = "Terminator RAT"
        category = "INFO"
        filetype = "memory"
        ref1 = "http://www.fireeye.com/blog/technical/malware-research/2013/10/evasive-tactics-terminator-rat.html"

    strings:
        $a = "Accelorator"
        $b = "<html><title>12356</title><body>"

    condition:
        all of them
}
