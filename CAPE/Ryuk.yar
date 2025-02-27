rule Ryuk
{
    meta:
        id = "6fbMmeYcPoDqKvhobOCCJa"
        fingerprint = "v1_sha256_b4463993d8956e402b927a3dcfa2ca9693a959908187f720372f2d3a40e6db0c"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Ryuk Payload"
        category = "INFO"
        cape_type = "Ryuk Payload"

    strings:
        $ext = ".RYK" wide
        $readme = "RyukReadMe.txt" wide
        $main = "InvokeMainViaCRT"
        $code = {48 8B 4D 10 48 8B 03 48 C1 E8 07 C1 E0 04 F7 D0 33 41 08 83 E0 10 31 41 08 48 8B 4D 10 48 8B 03 48 C1 E8 09 C1 E0 03 F7 D0 33 41 08 83 E0 08 31 41 08}
    condition:
        uint16(0) == 0x5A4D and 3 of ($*)
}
