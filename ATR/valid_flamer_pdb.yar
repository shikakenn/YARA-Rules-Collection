rule apt_flamer_pdb
{
    meta:
        id = "3MpUe0oACB8vnbzesD6txY"
        fingerprint = "v1_sha256_3c1d3d015e086cff1f3d5add39397d8ed251b12144b31d8547165cbd0217735c"
        version = "1.0"
        date = "2012-05-29"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Flamer based on the PDB"
        category = "INFO"
        reference = "https://www.forcepoint.com/ko/blog/x-labs/flameflamerskywiper-one-most-advanced-malware-found-yet"
        hash = "554924ebdde8e68cb8d367b8e9a016c5908640954ec9fb936ece07ac4c5e1b75"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Flamer"
        actor_group = "Unknown"

     strings:

         $pdb = "\\Projects\\Jimmy\\jimmydll_v2.0\\JimmyForClan\\Jimmy\\bin\\srelease\\jimmydll\\indsvc32.pdb"

     condition:

        uint16(0) == 0x5a4d and 
        filesize < 500KB and 
        any of them
}
