rule win_mgbot_auto {

    meta:
        id = "3YIwfQNrLJZOzehcxn1Kke"
        fingerprint = "v1_sha256_7310ce51cc81391fc78e9881bf8f490b2a783d4789728f7661df3e6bdca512d7"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mgbot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mgbot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 5b 8be5 5d c20800 6808020000 e8???????? }
            // n = 6, score = 200
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   6808020000           | push                0x208
            //   e8????????           |                     

        $sequence_1 = { 8be5 5d c20800 6808020000 e8???????? }
            // n = 5, score = 200
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   6808020000           | push                0x208
            //   e8????????           |                     

        $sequence_2 = { 5d c20800 6808020000 e8???????? }
            // n = 4, score = 200
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   6808020000           | push                0x208
            //   e8????????           |                     

        $sequence_3 = { 5b 8be5 5d c20800 6808020000 }
            // n = 5, score = 200
            //   5b                   | pop                 ebx
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   6808020000           | push                0x208

        $sequence_4 = { 0f8553ffffff 5f 33c0 5e }
            // n = 4, score = 200
            //   0f8553ffffff         | jne                 0xffffff59
            //   5f                   | pop                 edi
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi

        $sequence_5 = { 6808020000 e8???????? 6804010000 8bf0 }
            // n = 4, score = 200
            //   6808020000           | push                0x208
            //   e8????????           |                     
            //   6804010000           | push                0x104
            //   8bf0                 | mov                 esi, eax

        $sequence_6 = { 8be5 5d c20800 6808020000 }
            // n = 4, score = 200
            //   8be5                 | mov                 esp, ebp
            //   5d                   | pop                 ebp
            //   c20800               | ret                 8
            //   6808020000           | push                0x208

        $sequence_7 = { 6808020000 e8???????? 6804010000 8bf0 6a00 56 }
            // n = 6, score = 200
            //   6808020000           | push                0x208
            //   e8????????           |                     
            //   6804010000           | push                0x104
            //   8bf0                 | mov                 esi, eax
            //   6a00                 | push                0
            //   56                   | push                esi

        $sequence_8 = { 6808020000 e8???????? 6804010000 8bf0 6a00 }
            // n = 5, score = 200
            //   6808020000           | push                0x208
            //   e8????????           |                     
            //   6804010000           | push                0x104
            //   8bf0                 | mov                 esi, eax
            //   6a00                 | push                0

        $sequence_9 = { 6808020000 e8???????? 6804010000 8bf0 6a00 56 e8???????? }
            // n = 7, score = 200
            //   6808020000           | push                0x208
            //   e8????????           |                     
            //   6804010000           | push                0x104
            //   8bf0                 | mov                 esi, eax
            //   6a00                 | push                0
            //   56                   | push                esi
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1677312
}
