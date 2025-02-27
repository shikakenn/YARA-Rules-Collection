rule BackdoorFCKG: CTB_Locker_Ransomware
{

    meta:
        id = "2a9v0ZNfbySaDL8409yf7H"
        fingerprint = "v1_sha256_a334b07053db66aa0fb2d2b2ca7f94c480509041724ddd4dd1708052d75baffb"
        version = "1.0"
        date = "2015-01-20"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "ISG"
        description = "CTB_Locker"
        category = "INFO"
        reference = "https://blogs.mcafee.com/mcafee-labs/rise-backdoor-fckq-ctb-locker"
        rule_version = "v1"
        malware_family = "Ransom:W32/CTBLocker"
        actor_group = "Unknown"

    strings:

        $string0 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        $stringl = "RNDBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" 
        $string2 = "keme132.DLL" 
        $string3 = "klospad.pdb" 

    condition:

        3 of them 
}
