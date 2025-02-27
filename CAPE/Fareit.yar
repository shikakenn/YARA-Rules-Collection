rule Fareit
{
    meta:
        id = "7G6OwDdzQO6yn9MkYVTa0Q"
        fingerprint = "v1_sha256_ed35391ffc949219f380da3f22bc8397a7d5c742bd68e227c3becdebcab5cf83"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Fareit Payload"
        category = "INFO"
        cape_type = "Fareit Payload"

    strings:
        $string1 = {0D 0A 09 09 0D 0A 0D 0A 09 20 20 20 3A 6B 74 6B 20 20 20 0D 0A 0D 0A 0D 0A 20 20 20 20 20 64 65 6C 20 20 20 20 09 20 25 31 20 20 0D 0A 09 69 66 20 20 09 09 20 65 78 69 73 74 20 09 20 20 20 25 31 20 20 09 20 20 67 6F 74 6F 20 09 0D 20 6B 74 6B 0D 0A 20 64 65 6C 20 09 20 20 25 30 20 00}
    condition:
        uint16(0) == 0x5A4D and any of ($string*)
}
