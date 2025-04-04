rule Kingslayer_codekey
{
    meta:
        id = "74EjsZYDdBDCk7fkvt5hee"
        fingerprint = "v1_sha256_8c1b04f7530400691abe0d653f94a611632957f994aaabce4ba1cb7a616afe40"
        version = "1.0"
        date = "03 February 2017"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "RSA Research"
        description = "detects Win32 files signed with stolen code signing key used in Kingslayer attack"
        category = "INFO"
        reference = "http://firstwat.ch/kingslayer"
        hash0 = "fbb7de06dcb6118e060dd55720b51528"
        hash1 = "3974a53de0601828e272136fb1ec5106"
        hash2 = "f97a2744a4964044c60ac241f92e05d7"
        hash3 = "76ab4a360b59fe99be1ba7b9488b5188"
        hash4 = "1b57396c834d2eb364d28eb0eb28d8e4"

strings:
    $val0 = { 31 33 31 31 30 34 31 39 33 39 31 39 5A 17 0D 31 35 31 31 30 34 31 39 33 39 31 39 5A }
    $ven0 = { 41 6C 74 61 69 72 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 }
condition:
    uint16(0) == 0x5A4D and $val0 and $ven0
}
