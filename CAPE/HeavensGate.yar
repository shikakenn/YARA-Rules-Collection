rule HeavensGate
{
    meta:
        id = "3o0R6udtMqA9kfAPT4FH3w"
        fingerprint = "v1_sha256_e9842d0cc79e2f33d72a542266f613dc2d2bc7c6338269100e47dbe07f7c38b4"
        version = "1.0"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CAPE"
        author = "kevoreilly"
        description = "Heaven's Gate: Switch from 32-bit to 64-mode"
        category = "INFO"
        cape_type = "Heaven's Gate"

    strings:
        $gate_v1 = {6A 33 E8 00 00 00 00 83 04 24 05 CB}
        $gate_v2 = {9A 00 00 00 00 33 00 89 EC 5D C3 48 83 EC 20 E8 00 00 00 00 48 83 C4 20 CB}
        $gate_v3 = {5A 66 BB 33 00 66 53 50 89 E0 83 C4 06 FF 28}

    condition:
        ($gate_v1 or $gate_v2 or $gate_v3)
}
