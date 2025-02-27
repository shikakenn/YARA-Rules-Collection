rule havex_backdoor_pdb {
     
    meta:
        id = "7YUVn8Klia9BxPcHdUnCl5"
        fingerprint = "v1_sha256_dc50475b1ff2194306a0295f71860e4cc5ae7e126daa5d401b98cd2a0aadf1dd"
        version = "1.0"
        date = "2012-11-17"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect backdoor Havex based on PDB"
        category = "INFO"
        reference = "https://www.f-secure.com/v-descs/backdoor_w32_havex.shtml"
        hash = "0f4046be5de15727e8ac786e54ad7230807d26ef86c3e8c0e997ea76ab3de255"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Havex"
        actor_group = "Unknown"

     strings:

         $pdb = "\\Workspace\\PhalangX 3D\\Src\\Build\\Release\\Phalanx-3d.ServerAgent.pdb"
         $pdb1 = "\\Workspace\\PhalangX 3D\\Src\\Build\\Release\\Tmprovider.pdb"

    condition:

         uint16(0) == 0x5a4d and
         filesize < 500KB and
         any of them
}
