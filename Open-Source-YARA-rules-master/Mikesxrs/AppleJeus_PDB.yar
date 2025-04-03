rule AppleJeus_PDB
{
    meta:
        id = "4CeTUXpv8CS8irL1CC8Mtd"
        fingerprint = "v1_sha256_d8868949dacb8b53e87dd3c41877c7336c3874d199eef5350316674486d87050"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mikesxrs"
        description = "PDB Path in  malware"
        category = "INFO"
        reference = "https://securelist.com/operation-applejeus/87553/"

  strings: 
    $pdb1 = "Z:\\jeus\\downloader\\downloader_exe_vs2010\\Release\\dloader.pdb"
    $pdb2 = "Z:\\jeus\\downloader\\"
    $pdb3 = "H:\\DEV\\TManager\\all_BOSS_troy\\T_4.2\\T_4.2\\Server_\\x64\\Release\\ServerDll.pdb"
    $pdb4 = "H:\\DEV\\TManager\\DLoader\\20180702\\dloader\\WorkingDir\\Output\\00000009\\Release\\dloader.pdb"
    $pdb5 = "H:\\DEV\\TManager\\DLoader\\20180702\\dloader\\WorkingDir\\Output\\00000006\\Release\\dloader.pdb"
    $pdb6 = "H:\\DEV\\TManager\\"
  
  condition:
    any of them

}
