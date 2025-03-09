rule Ransomware_Win_DARKSIDE_v1__1
{
    meta:
        id = "4DVd4jLjmqbN2p4weT72Ze"
        fingerprint = "v1_sha256_b3612510bd1f2ca7543e217e97037b02d312bcda2b2df16d9be3216749ea4beb"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "FireEye"
        description = "Detection for early versions of DARKSIDE ransomware samples based on the encryption mode configuration values"
        category = "INFO"
        reference = "https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations"
        date_created = "2021-03-22"
        md5 = "1a700f845849e573ab3148daef1a3b0b"

    strings:
        $consts = { 80 3D [4] 01 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] 00 00 04 00 [1-10] 00 00 00 00 [1-30] 80 3D [4] 02 [1-10] 03 00 00 00 [1-10] 03 00 00 00 [1-10] FF FF FF FF [1-10] FF FF FF FF [1-30] 03 00 00 00 [1-10] 03 00 00 00 }
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and $consts
}
