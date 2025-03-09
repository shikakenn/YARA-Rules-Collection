rule SpyGate_v2_9
{
    meta:
        id = "1q6R2uWUkgUsoidowDQF50"
        fingerprint = "v1_sha256_a18bcb608daaa7974f707d381657a22aedfc34bb5246c6bf4c6b71e8eef859ed"
        version = "1.0"
        date = "2014/09"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "McAfee"
        description = "NA"
        category = "INFO"
        reference = "https://blogs.mcafee.com/mcafee-labs/middle-east-developer-spygate-struts-stuff-online"
        maltype = "Spygate v2.9 Remote Access Trojan"
        filetype = "exe"

    strings:
        $1 = "shutdowncomputer" wide
        $2 = "shutdown -r -t 00" wide
        $3 = "blockmouseandkeyboard" wide
        $4 = "ProcessHacker"
        $5 = "FileManagerSplit" wide
    condition:
        all of them
}
