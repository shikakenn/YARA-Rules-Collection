rule apt_elise_pdb {
     
    meta:
        id = "3OxTGgGU54QUxlCanXvUET"
        fingerprint = "v1_sha256_bb7eee8082aa0f6634a8c4cdb9cbe0e2a7f00b97e48609c81a21bdaac64a5496"
        version = "1.0"
        date = "2017-05-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "ATR"
        author = "Marc Rivero | McAfee ATR Team"
        description = "Rule to detect Elise APT based on the PDB reference"
        category = "INFO"
        reference = "https://attack.mitre.org/software/S0081/"
        hash = "b426dbe0f281fe44495c47b35c0fb61b28558b5c8d9418876e22ec3de4df9e7b"
        rule_version = "v1"
        malware_family = "Backdoor:W32/Elise"
        actor_group = "Unknown"

     strings:

         $pdb = "\\lstudio\\projects\\lotus\\elise\\Release\\EliseDLL\\i386\\EliseDLL.pdb"
         $pdb1 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\SetElise.pdb"
         $pdb2 = "\\lstudio\\projects\\lotus\\elise\\Release\\SetElise\\i386\\SetElise.pdb"
         $pdb3 = "\\LStudio\\Projects\\Lotus\\Elise\\Release\\Uninstaller.pdb"
         $pdb4 = "\\lstudio\\projects\\lotus\\evora\\Release\\EvoraDLL\\i386\\EvoraDLL.pdb"

     condition:

      uint16(0) == 0x5a4d and 
      filesize < 50KB and 
      any of them
}
