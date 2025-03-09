rule FE_APT_9002_rat

{

    meta:
        id = "3yNSQ3UPnAc8HWAD2iHeOj"
        fingerprint = "v1_sha256_575914ba8d502883ea4c69a7912b703e27ffa8c260f8539e496d0f6c4b3a4236"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye Labs"
        description = "NA"
        category = "INFO"
        reference = "https://www.fireeye.com/blog/threat-research/2013/11/operation-ephemeral-hydra-ie-zero-day-linked-to-deputydog-uses-diskless-method.html"

    strings:

        $mz = {4d 5a}

        $a = "rat_UnInstall" wide ascii

    condition:

        ($mz at 0) and $a

}
