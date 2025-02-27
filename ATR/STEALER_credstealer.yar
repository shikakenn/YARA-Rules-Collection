rule STEALER_credstealesy
{
    
    meta:
        id = "6FEXP0DY831bqkxfZH2IOo"
        fingerprint = "v1_sha256_3d007fc0d2e2eb3d8f0c2b86dd01ede482e72f6c67fd6d284d77c47b53021b3c"
        version = "1.0"
        date = "2015-05-08"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "IsecG – McAfee Labs"
        description = "Generic Rule to detect the CredStealer Malware"
        category = "INFO"
        reference = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/when-hackers-get-hacked-the-malware-servers-of-a-data-stealing-campaign/"
        rule_version = "v1"
        malware_family = "Stealer:W32/CredStealer"
        actor_group = "Unknown"

    strings:

        $my_hex_string = "CurrentControlSet\\Control\\Keyboard Layouts\\" wide //malware trying to get keyboard layout
        $my_hex_string2 = {89 45 E8 3B 7D E8 7C 0F 8B 45 E8 05 FF 00 00 00 2B C7 89 45 E8} //specific decryption module

    condition:

        $my_hex_string and $my_hex_string2
    }
