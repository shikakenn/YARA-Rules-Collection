rule Kovter
{
    meta:
        id = "7YT2wMjxWiuwDrnbMHDFHW"
        fingerprint = "v1_sha256_888fccb8fbfbe6c05ec63bc5658b4743f8e10a96ef51b3868c2ff94afec76f2d"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Kovter Payload"
        category = "INFO"
        cape_type = "Kovter Payload"

    strings:
        $a1 = "chkok"
        $a2 = "k2Tdgo"
        $a3 = "13_13_13"
        $a4 = "Win Server 2008 R2"
    condition:
        uint16(0) == 0x5A4D and (all of ($a*))
}
