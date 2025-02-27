rule PetrWrap
{
    meta:
        id = "1ok9zMdRaRaWiwP6c2AFFN"
        fingerprint = "v1_sha256_6dd1cf5639b63d0ab41b24080dad68d285f2e3969ad34fd724c83e7a0dd4b968"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "PetrWrap Payload"
        category = "INFO"
        cape_type = "PetrWrap Payload"

    strings:
        $a1 = "http://petya3jxfp2f7g3i.onion/"
        $a2 = "http://petya3sen7dyko2n.onion"

        $b1 = "http://mischapuk6hyrn72.onion/"
        $b2 = "http://mischa5xyix2mrhd.onion/"
    condition:
        uint16(0) == 0x5A4D and (any of ($a*)) and (any of ($b*))
}
