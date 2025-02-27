rule LokiBot
{
    meta:
        id = "71JszpDzu9wcuDRbHNCcu7"
        fingerprint = "v1_sha256_a5b3d518371138740e913d2d6ce4fa22d3da5cea7e034c7d6b4b502e6bf44b06"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "LokiBot Payload"
        category = "INFO"
        cape_type = "LokiBot Payload"

    strings:
        $a1 = "DlRycq1tP2vSeaogj5bEUFzQiHT9dmKCn6uf7xsOY0hpwr43VINX8JGBAkLMZW"
        $a2 = "last_compatible_version"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
