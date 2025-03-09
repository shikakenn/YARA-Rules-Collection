
rule conbot_packer {
    meta:
        id = "4DrLafUEgien6fasDptqJH"
        fingerprint = "v1_sha256_1852603d024c1ceac1d3d13dc15b226e657a95b0b56533710a8eaafcb1ad7579"
        version = "1.0"
        modified = "2025-03-10"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Undefined"
        description = "NA"
        category = "INFO"
        decoder = "conbot_packer.py"

    strings:
        $pic_code = { FCE8 8600 0000 6089 E531 D264 8B52 308B 520C 8B52 148B 7228 0FB7 4A26 31FF 31C0 AC3C 617C 022C 20C1 CF0D 01C7 E2F0 5257 8B }

    condition:
        IsPeFile and $pic_code
}

