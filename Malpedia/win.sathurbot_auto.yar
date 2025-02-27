rule win_sathurbot_auto {

    meta:
        id = "5Q208adDArF4VL14Uc6X68"
        fingerprint = "v1_sha256_516fbdaf796971a35966077b409dae2049cf7a15611af7b3fda85f6cf94f88db"
        version = "1"
        date = "2024-10-31"
        modified = "2025-02-27"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "MALPEDIA"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.sathurbot."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sathurbot"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { f6c101 0f94c0 813d????????0a000000 0f9cc1 08c1 b8f90f07b5 b94cba8e03 }
            // n = 7, score = 100
            //   f6c101               | test                cl, 1
            //   0f94c0               | sete                al
            //   813d????????0a000000     |     
            //   0f9cc1               | setl                cl
            //   08c1                 | or                  cl, al
            //   b8f90f07b5           | mov                 eax, 0xb5070ff9
            //   b94cba8e03           | mov                 ecx, 0x38eba4c

        $sequence_1 = { eb13 8a55fa 8a75fb 08d6 f6c601 be09a730d3 0f45f1 }
            // n = 7, score = 100
            //   eb13                 | jmp                 0x15
            //   8a55fa               | mov                 dl, byte ptr [ebp - 6]
            //   8a75fb               | mov                 dh, byte ptr [ebp - 5]
            //   08d6                 | or                  dh, dl
            //   f6c601               | test                dh, 1
            //   be09a730d3           | mov                 esi, 0xd330a709
            //   0f45f1               | cmovne              esi, ecx

        $sequence_2 = { f6c101 0f94c0 813d????????0a000000 0f9cc1 08c1 b8fb0334f5 b995c6f26e }
            // n = 7, score = 100
            //   f6c101               | test                cl, 1
            //   0f94c0               | sete                al
            //   813d????????0a000000     |     
            //   0f9cc1               | setl                cl
            //   08c1                 | or                  cl, al
            //   b8fb0334f5           | mov                 eax, 0xf53403fb
            //   b995c6f26e           | mov                 ecx, 0x6ef2c695

        $sequence_3 = { f6c101 0f94c0 813d????????0a000000 0f9cc1 08c1 b8d60de432 b9dc519a31 }
            // n = 7, score = 100
            //   f6c101               | test                cl, 1
            //   0f94c0               | sete                al
            //   813d????????0a000000     |     
            //   0f9cc1               | setl                cl
            //   08c1                 | or                  cl, al
            //   b8d60de432           | mov                 eax, 0x32e40dd6
            //   b9dc519a31           | mov                 ecx, 0x319a51dc

        $sequence_4 = { f6c101 0f94c0 813d????????0a000000 0f9cc1 08c1 b88c88bb32 b93cd77390 }
            // n = 7, score = 100
            //   f6c101               | test                cl, 1
            //   0f94c0               | sete                al
            //   813d????????0a000000     |     
            //   0f9cc1               | setl                cl
            //   08c1                 | or                  cl, al
            //   b88c88bb32           | mov                 eax, 0x32bb888c
            //   b93cd77390           | mov                 ecx, 0x9073d73c

        $sequence_5 = { c744240400000000 ff15???????? 83ec18 8945e4 837de400 0f9545eb a1???????? }
            // n = 7, score = 100
            //   c744240400000000     | mov                 dword ptr [esp + 4], 0
            //   ff15????????         |                     
            //   83ec18               | sub                 esp, 0x18
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   837de400             | cmp                 dword ptr [ebp - 0x1c], 0
            //   0f9545eb             | setne               byte ptr [ebp - 0x15]
            //   a1????????           |                     

        $sequence_6 = { b8a152f86d b9518159e1 0f45c1 b9a152f86d bac9ebae71 0f45ca bf7994f31d }
            // n = 7, score = 100
            //   b8a152f86d           | mov                 eax, 0x6df852a1
            //   b9518159e1           | mov                 ecx, 0xe1598151
            //   0f45c1               | cmovne              eax, ecx
            //   b9a152f86d           | mov                 ecx, 0x6df852a1
            //   bac9ebae71           | mov                 edx, 0x71aeebc9
            //   0f45ca               | cmovne              ecx, edx
            //   bf7994f31d           | mov                 edi, 0x1df39479

        $sequence_7 = { eb02 31d2 83f90a 7c0f 8d48ff 0fafc8 83e101 }
            // n = 7, score = 100
            //   eb02                 | jmp                 4
            //   31d2                 | xor                 edx, edx
            //   83f90a               | cmp                 ecx, 0xa
            //   7c0f                 | jl                  0x11
            //   8d48ff               | lea                 ecx, [eax - 1]
            //   0fafc8               | imul                ecx, eax
            //   83e101               | and                 ecx, 1

        $sequence_8 = { f6c101 0f94c0 813d????????0a000000 0f9cc1 08c1 b8eab7bd0b b966078151 }
            // n = 7, score = 100
            //   f6c101               | test                cl, 1
            //   0f94c0               | sete                al
            //   813d????????0a000000     |     
            //   0f9cc1               | setl                cl
            //   08c1                 | or                  cl, al
            //   b8eab7bd0b           | mov                 eax, 0xbbdb7ea
            //   b966078151           | mov                 ecx, 0x51810766

        $sequence_9 = { e9???????? 81fe4cc3b5b8 89f3 0f852cfeffff 8b5c240c e9???????? 81fe45dc43a2 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   81fe4cc3b5b8         | cmp                 esi, 0xb8b5c34c
            //   89f3                 | mov                 ebx, esi
            //   0f852cfeffff         | jne                 0xfffffe32
            //   8b5c240c             | mov                 ebx, dword ptr [esp + 0xc]
            //   e9????????           |                     
            //   81fe45dc43a2         | cmp                 esi, 0xa243dc45

    condition:
        7 of them and filesize < 2727936
}
