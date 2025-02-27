rule win_deathransom_auto {

    meta:
        id = "5AirjrLwCINb86P5D175K0"
        fingerprint = "v1_sha256_51420be8374b7a80642a50bf14b9acdb6936ed5b62767040db7c66a1d7ee7900"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.deathransom."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deathransom"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 7508 4e 83e804 85f6 7ff3 5f }
            // n = 6, score = 100
            //   7508                 | jne                 0xa
            //   4e                   | dec                 esi
            //   83e804               | sub                 eax, 4
            //   85f6                 | test                esi, esi
            //   7ff3                 | jg                  0xfffffff5
            //   5f                   | pop                 edi

        $sequence_1 = { 2345e8 8b5dd8 0bd8 03d9 8b4d88 8bd1 895dd8 }
            // n = 7, score = 100
            //   2345e8               | and                 eax, dword ptr [ebp - 0x18]
            //   8b5dd8               | mov                 ebx, dword ptr [ebp - 0x28]
            //   0bd8                 | or                  ebx, eax
            //   03d9                 | add                 ebx, ecx
            //   8b4d88               | mov                 ecx, dword ptr [ebp - 0x78]
            //   8bd1                 | mov                 edx, ecx
            //   895dd8               | mov                 dword ptr [ebp - 0x28], ebx

        $sequence_2 = { 03ca 8d5601 3bcf 8bc1 0f42d6 8b75e0 2bc7 }
            // n = 7, score = 100
            //   03ca                 | add                 ecx, edx
            //   8d5601               | lea                 edx, [esi + 1]
            //   3bcf                 | cmp                 ecx, edi
            //   8bc1                 | mov                 eax, ecx
            //   0f42d6               | cmovb               edx, esi
            //   8b75e0               | mov                 esi, dword ptr [ebp - 0x20]
            //   2bc7                 | sub                 eax, edi

        $sequence_3 = { c1e803 33c8 8b5df8 03d1 8bc7 0355c8 8bcf }
            // n = 7, score = 100
            //   c1e803               | shr                 eax, 3
            //   33c8                 | xor                 ecx, eax
            //   8b5df8               | mov                 ebx, dword ptr [ebp - 8]
            //   03d1                 | add                 edx, ecx
            //   8bc7                 | mov                 eax, edi
            //   0355c8               | add                 edx, dword ptr [ebp - 0x38]
            //   8bcf                 | mov                 ecx, edi

        $sequence_4 = { 8d8d90fdffff e8???????? 6a50 8d8590fdffff 50 8d8578feffff 50 }
            // n = 7, score = 100
            //   8d8d90fdffff         | lea                 ecx, [ebp - 0x270]
            //   e8????????           |                     
            //   6a50                 | push                0x50
            //   8d8590fdffff         | lea                 eax, [ebp - 0x270]
            //   50                   | push                eax
            //   8d8578feffff         | lea                 eax, [ebp - 0x188]
            //   50                   | push                eax

        $sequence_5 = { 035594 8bc7 c1c807 33c8 8bc7 c1e803 33c8 }
            // n = 7, score = 100
            //   035594               | add                 edx, dword ptr [ebp - 0x6c]
            //   8bc7                 | mov                 eax, edi
            //   c1c807               | ror                 eax, 7
            //   33c8                 | xor                 ecx, eax
            //   8bc7                 | mov                 eax, edi
            //   c1e803               | shr                 eax, 3
            //   33c8                 | xor                 ecx, eax

        $sequence_6 = { 81c2fc6d2c4d 03d0 8b45ec 8bc8 03da c1c00a c1c90d }
            // n = 7, score = 100
            //   81c2fc6d2c4d         | add                 edx, 0x4d2c6dfc
            //   03d0                 | add                 edx, eax
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   8bc8                 | mov                 ecx, eax
            //   03da                 | add                 ebx, edx
            //   c1c00a               | rol                 eax, 0xa
            //   c1c90d               | ror                 ecx, 0xd

        $sequence_7 = { 6880000000 8d8538ffffff 50 ffd1 808d38ffffffc0 8d8538ffffff 804db701 }
            // n = 7, score = 100
            //   6880000000           | push                0x80
            //   8d8538ffffff         | lea                 eax, [ebp - 0xc8]
            //   50                   | push                eax
            //   ffd1                 | call                ecx
            //   808d38ffffffc0       | or                  byte ptr [ebp - 0xc8], 0xc0
            //   8d8538ffffff         | lea                 eax, [ebp - 0xc8]
            //   804db701             | or                  byte ptr [ebp - 0x49], 1

        $sequence_8 = { 57 894df8 c745fc00000000 8975f0 895d0c 8b02 8bfe }
            // n = 7, score = 100
            //   57                   | push                edi
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8975f0               | mov                 dword ptr [ebp - 0x10], esi
            //   895d0c               | mov                 dword ptr [ebp + 0xc], ebx
            //   8b02                 | mov                 eax, dword ptr [edx]
            //   8bfe                 | mov                 edi, esi

        $sequence_9 = { 0fafc3 2bf8 8d87ffff0000 8945fc 3bc1 720a }
            // n = 6, score = 100
            //   0fafc3               | imul                eax, ebx
            //   2bf8                 | sub                 edi, eax
            //   8d87ffff0000         | lea                 eax, [edi + 0xffff]
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   3bc1                 | cmp                 eax, ecx
            //   720a                 | jb                  0xc

    condition:
        7 of them and filesize < 133120
}
