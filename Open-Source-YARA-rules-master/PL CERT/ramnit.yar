import "pe"

rule ramnit_general {

    meta:
        id = "6xRTeFQc3Px9JukSir5sBp"
        fingerprint = "v1_sha256_f4bcb016d7f8c082e98c65b88f4eb42e4bd3a0f047248d7e5b32c085e76928a1"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "nazywam"
        description = "NA"
        category = "INFO"
        reference = "https://www.cert.pl/en/news/single/ramnit-in-depth-analysis/"
        module = "ramnit"

  strings:
    $guid = "{%08X-%04X-%04X-%04X-%08X%04X}"

    $md5_magic_1 = "15Bn99gT"
    $md5_magic_2 = "1E4hNy1O"

    $init_dga = { C7 ?? ?? ?? ?? ?? FF FF FF FF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0B C0 75 ?? }

    $xor_secret = { 8A ?? ?? 32 ?? 88 ?? 4? 4? E2 ?? }

    $init_function = { FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 }

    $dga_rand_int = { B9 1D F3 01 00 F7 F1 8B C8 B8 A7 41 00 00 }

    $cookies = "\\cookies4.dat"

    $s3 = "pdatesDisableNotify"

    $get_domains = { a3 [4] a1 [4] 80 3? 00 75 ?? c7 05 [4] ff ff ff ff ff 35 [4] ff 35 [4] ff 35 [4] e8 }

    $add_tld = { 55 8B EC  83 ?? ?? 57 C7 ?? ?? 00 00 00 00 B? ?? ?? ?? ?? 8B ?? ?? 3B ?? ?? 75 ?? 8B ?? }

    $get_port = { 90 68 [4] 68 [4] FF 35 [4] FF 35 [4] E8 [4] 83 }

  condition:
    $init_dga and $init_function and 2 of ($guid, $md5_magic_*, $cookies, $s3) and any of ( $get_port, $add_tld, $dga_rand_int, $get_domains, $xor_secret)
}

rule ramnit_dll {

    meta:
        id = "5myPbXPH0UbkZdZqwRUoxl"
        fingerprint = "v1_sha256_dd41b0c7571341727704181a87efe599678b37f4819c81008fa3c2247e4383ea"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "nazywam"
        description = "NA"
        category = "INFO"
        reference = "https://www.cert.pl/en/news/single/ramnit-in-depth-analysis/"
        module = "ramnit"

  condition:
    pe.characteristics and pe.DLL and ramnit_general
}

rule ramnit_injector {

    meta:
        id = "3bBtu0vZEfbyDA1ZnIMFYA"
        fingerprint = "v1_sha256_2120e342d29ee480063ca2e57e97270706982e9bfbc34be5038eb05a4cbcb144"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "nazywam"
        description = "NA"
        category = "INFO"
        reference = "https://www.cert.pl/en/news/single/ramnit-in-depth-analysis/"
        module = "ramnit"

  strings:
    $unpack_dlls = { B8 [4] 50 E8 [4] A3 [4] 68 [4] 68 [4] FF [5] E8 [4] B8 [4] 50 E8 [4] A3 [4] 68 [4] 68 [4] FF [5] E8 }

  condition:
    $unpack_dlls and ramnit_general
}
