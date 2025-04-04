rule SyberSpace_PDB
{
    meta:
        id = "69Gn8IdOwwFuqX6BQP0s4J"
        fingerprint = "v1_sha256_6c6b31fda99be1a44432b3794ffd2e818617bbf0e545689fea53682002147066"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "mikesxrs"
        description = "PDB Path in httpbrowser malware"
        category = "INFO"
        reference = "hhttps://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage"

  strings: 
    $pdb1 = "c:\\Users\\SyberSpace\\Desktop\\Uac\\Release\\Uac.pdb"
    $pdb2 = "c:\\Users\\SyberSpace\\Desktop\\code\\Release\\code.pdb"
    $pdb3 = "c:\\Users\\SyberSpace\\Desktop\\Local\\Release\\Local.pdb"
    $pdb4 = "c:\\Users\\SyberSpace\\Desktop\\gsecdump\\hashdump\\Release\\hashdump.pdb"
    $pdb5 = "c:\\Users\\SyberSpace\\Desktop\\inline_asm_vc\\test\\Release\test.pdb"
    $pdb6 = "c:\\Users\\SyberSpace\\Desktop\\RemCom_SRC_1.2\\RemCom\\Release\\RemCom.pdb"
    $pdb7 = "c:\\Users\\SyberSpace\\Desktop\\owa\\HttpsExts\\HttpsExts\\HttpsExts\\obj\\Release\\OwaAuth.pdb"
  $pdb8 = "c:\\Users\\SyberSpace\\Desktop\\"
    
  condition:
    any of them
}
