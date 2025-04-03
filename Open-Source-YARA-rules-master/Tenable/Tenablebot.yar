rule Tenablebot
{
    meta:
        id = "18vflypXgaKs0nFNAfteqH"
        fingerprint = "v1_sha256_19ed04c3f88b3724172f6cee57a485f463305c48e72defb9513845f68ac88f37"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "tenable"
        description = "NA"
        category = "INFO"
        reference = "https://www.tenable.com/blog/threat-hunting-with-yara-and-nessus"

    strings:
        $channel = "#secret_tenable_bot_channel"
        $version = "Tenable Bot version 0.1"
        $version_command = "!version"
        $exec_command = "!exec"
        $user = "USER tenable_bot 8 * :doh!"
    condition:
        all of them
}
