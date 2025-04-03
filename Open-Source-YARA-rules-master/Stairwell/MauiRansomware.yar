rule MauiRansomware
{
    meta:
        id = "5tHXTpGT7plBbd3UNMj5Uy"
        fingerprint = "v1_sha256_b3e943821a06e8bcc2016a70825f3ccdd0ee292b280de0c659bdfdca30c9db1f"
        version = "0.1"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Silas Cutler (Silas@Stairwell.com)"
        description = "Detection for Maui Ransomware"
        category = "INFO"
        reference = "https://stairwell.com/wp-content/uploads/2022/07/Stairwell-Threat-Report-Maui-Ransomware.pdf"

strings:
$ = "Unable to read public key info." wide
$ = "it by <Godhead> using -maui option." wide
$ = "Incompatible public key version." wide
$ = "maui.key" wide
$ = "maui.evd" wide
$ = "Unable to encrypt private key" wide
$ = "Unable to create evidence file" wide
$ = "PROCESS_GOINGON[%d%% / %d%%]: %s" wide
$ = "demigod.key" wide
$ = "Usage: maui [-ptx] [PATH]" wide
$ = "-p dir: Set Log Directory (Default: Current Directory)" wide
$ = "-t n: Set Thread Count (Default: 1)" wide
$ = "-x: Self Melt (Default: No)" wide
// File header loading (x32-bit)
$ = { 44 24 24 44 49 56 45 ?? 44 24 28 01 00 00 00 ?? 44 24 2C 10 00 00 00 }
$ = { 44 4F 47 44 ?? ?? 04 01 00 00 00 }
condition:
3 of them or
(
uint32(filesize-8) == 0x00000001 and
uint32(filesize-12) == 0x5055424B
)
}
