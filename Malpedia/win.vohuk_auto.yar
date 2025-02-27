rule win_vohuk_auto {

    meta:
        id = "i7IxvjRiFA4b7oraM6gig"
        fingerprint = "v1_sha256_a782dfb427f32a7fe3f5e7a12676df6b8f0aca1f4f78c54f0e9a25741f4d58aa"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.vohuk."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vohuk"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { be8d000000 8b45c4 83c30c 40 }
            // n = 4, score = 100
            //   be8d000000           | mov                 esi, 0x8d
            //   8b45c4               | mov                 eax, dword ptr [ebp - 0x3c]
            //   83c30c               | add                 ebx, 0xc
            //   40                   | inc                 eax

        $sequence_1 = { ba4786ac2e 6a21 e8???????? 57 ffd0 8b0d???????? ba4786ac2e }
            // n = 7, score = 100
            //   ba4786ac2e           | mov                 edx, 0x2eac8647
            //   6a21                 | push                0x21
            //   e8????????           |                     
            //   57                   | push                edi
            //   ffd0                 | call                eax
            //   8b0d????????         |                     
            //   ba4786ac2e           | mov                 edx, 0x2eac8647

        $sequence_2 = { e8???????? 6801000100 6a08 56 ffd0 8b0d???????? ba0decbfd2 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   6801000100           | push                0x10001
            //   6a08                 | push                8
            //   56                   | push                esi
            //   ffd0                 | call                eax
            //   8b0d????????         |                     
            //   ba0decbfd2           | mov                 edx, 0xd2bfec0d

        $sequence_3 = { 8b857cfeffff 668985fcfeffff 8b8578feffff 668985fefeffff 8b8574feffff 66898500ffffff 8b8570feffff }
            // n = 7, score = 100
            //   8b857cfeffff         | mov                 eax, dword ptr [ebp - 0x184]
            //   668985fcfeffff       | mov                 word ptr [ebp - 0x104], ax
            //   8b8578feffff         | mov                 eax, dword ptr [ebp - 0x188]
            //   668985fefeffff       | mov                 word ptr [ebp - 0x102], ax
            //   8b8574feffff         | mov                 eax, dword ptr [ebp - 0x18c]
            //   66898500ffffff       | mov                 word ptr [ebp - 0x100], ax
            //   8b8570feffff         | mov                 eax, dword ptr [ebp - 0x190]

        $sequence_4 = { 8b8570ffffff 668985ccfeffff b8b8000000 668985cefeffff 668985d2feffff 8b856cffffff 668985d4feffff }
            // n = 7, score = 100
            //   8b8570ffffff         | mov                 eax, dword ptr [ebp - 0x90]
            //   668985ccfeffff       | mov                 word ptr [ebp - 0x134], ax
            //   b8b8000000           | mov                 eax, 0xb8
            //   668985cefeffff       | mov                 word ptr [ebp - 0x132], ax
            //   668985d2feffff       | mov                 word ptr [ebp - 0x12e], ax
            //   8b856cffffff         | mov                 eax, dword ptr [ebp - 0x94]
            //   668985d4feffff       | mov                 word ptr [ebp - 0x12c], ax

        $sequence_5 = { c745e49700c500 c745e882008200 c745ec86008000 c745f08f008f00 c745f4d600cd00 c745f8cb008300 c745fc8300f100 }
            // n = 7, score = 100
            //   c745e49700c500       | mov                 dword ptr [ebp - 0x1c], 0xc50097
            //   c745e882008200       | mov                 dword ptr [ebp - 0x18], 0x820082
            //   c745ec86008000       | mov                 dword ptr [ebp - 0x14], 0x800086
            //   c745f08f008f00       | mov                 dword ptr [ebp - 0x10], 0x8f008f
            //   c745f4d600cd00       | mov                 dword ptr [ebp - 0xc], 0xcd00d6
            //   c745f8cb008300       | mov                 dword ptr [ebp - 8], 0x8300cb
            //   c745fc8300f100       | mov                 dword ptr [ebp - 4], 0xf10083

        $sequence_6 = { 03c2 0fbec0 6bc073 040c 02c1 30440dd0 41 }
            // n = 7, score = 100
            //   03c2                 | add                 eax, edx
            //   0fbec0               | movsx               eax, al
            //   6bc073               | imul                eax, eax, 0x73
            //   040c                 | add                 al, 0xc
            //   02c1                 | add                 al, cl
            //   30440dd0             | xor                 byte ptr [ebp + ecx - 0x30], al
            //   41                   | inc                 ecx

        $sequence_7 = { 69c0f6000000 2bc8 81c1cc000000 66318c74ea000000 46 83fe27 72d1 }
            // n = 7, score = 100
            //   69c0f6000000         | imul                eax, eax, 0xf6
            //   2bc8                 | sub                 ecx, eax
            //   81c1cc000000         | add                 ecx, 0xcc
            //   66318c74ea000000     | xor                 word ptr [esp + esi*2 + 0xea], cx
            //   46                   | inc                 esi
            //   83fe27               | cmp                 esi, 0x27
            //   72d1                 | jb                  0xffffffd3

        $sequence_8 = { 6a22 e8???????? 68???????? 53 ffd0 8b7d90 8b7510 }
            // n = 7, score = 100
            //   6a22                 | push                0x22
            //   e8????????           |                     
            //   68????????           |                     
            //   53                   | push                ebx
            //   ffd0                 | call                eax
            //   8b7d90               | mov                 edi, dword ptr [ebp - 0x70]
            //   8b7510               | mov                 esi, dword ptr [ebp + 0x10]

        $sequence_9 = { 8bec 81ec5c080000 8d45a8 ba44000000 56 8bf1 c60000 }
            // n = 7, score = 100
            //   8bec                 | mov                 ebp, esp
            //   81ec5c080000         | sub                 esp, 0x85c
            //   8d45a8               | lea                 eax, [ebp - 0x58]
            //   ba44000000           | mov                 edx, 0x44
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   c60000               | mov                 byte ptr [eax], 0

    condition:
        7 of them and filesize < 260096
}
