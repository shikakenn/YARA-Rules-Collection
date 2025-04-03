rule Remcos_RAT
{
    meta:
        id = "3QFcO42DOUws1YrHRy9l01"
        fingerprint = "v1_sha256_efd8c99eb8f8b43d8952b63e3dbe7d92d51c4311ac7906d00af366e077fd53a8"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        Description = "Deteccion del troyano Remcos"
        Author = "SadFud"
        Date = "08/08/2016"
        Hash = "f467114dd637c817b4c982fad55fe019"

    strings:
    $a = { 52 45 4d 43 4f 53 }
      $b = { 52 65 6d 63 6f 73 5f 4d 75 74 65 78 }
    
    condition:
    $a or $b 
    
}
