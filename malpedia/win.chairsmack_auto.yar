rule win_chairsmack_auto {

    meta:
        id = "A4e2FcHNjf6n45D3l8JEk"
        fingerprint = "v1_sha256_97781ffb695d6aa345e6e0e1fc6bc5189db5a22419050af0ce259dc4d2e28203"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.chairsmack."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chairsmack"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8b5d08 ebd3 83fe03 75cb 8b45c0 ff7050 ff75ec }
            // n = 7, score = 200
            //   8b5d08               | mov                 ebx, dword ptr [ebp + 8]
            //   ebd3                 | jmp                 0xffffffd5
            //   83fe03               | cmp                 esi, 3
            //   75cb                 | jne                 0xffffffcd
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   ff7050               | push                dword ptr [eax + 0x50]
            //   ff75ec               | push                dword ptr [ebp - 0x14]

        $sequence_1 = { 8b4de0 83c104 e9???????? 8b542408 8d420c 8b4adc 33c8 }
            // n = 7, score = 200
            //   8b4de0               | mov                 ecx, dword ptr [ebp - 0x20]
            //   83c104               | add                 ecx, 4
            //   e9????????           |                     
            //   8b542408             | mov                 edx, dword ptr [esp + 8]
            //   8d420c               | lea                 eax, [edx + 0xc]
            //   8b4adc               | mov                 ecx, dword ptr [edx - 0x24]
            //   33c8                 | xor                 ecx, eax

        $sequence_2 = { 50 8b4508 03c1 53 50 e8???????? 83c40c }
            // n = 7, score = 200
            //   50                   | push                eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   03c1                 | add                 eax, ecx
            //   53                   | push                ebx
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc

        $sequence_3 = { 8bff 8b06 8d8d5cfeffff 3bc1 7409 83780400 8d7004 }
            // n = 7, score = 200
            //   8bff                 | mov                 edi, edi
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   8d8d5cfeffff         | lea                 ecx, [ebp - 0x1a4]
            //   3bc1                 | cmp                 eax, ecx
            //   7409                 | je                  0xb
            //   83780400             | cmp                 dword ptr [eax + 4], 0
            //   8d7004               | lea                 esi, [eax + 4]

        $sequence_4 = { c745d000000000 720b ff759c e8???????? 83c404 8b4598 }
            // n = 6, score = 200
            //   c745d000000000       | mov                 dword ptr [ebp - 0x30], 0
            //   720b                 | jb                  0xd
            //   ff759c               | push                dword ptr [ebp - 0x64]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   8b4598               | mov                 eax, dword ptr [ebp - 0x68]

        $sequence_5 = { 7517 68cb0a0000 68???????? 68???????? e8???????? 83c40c 3bde }
            // n = 7, score = 200
            //   7517                 | jne                 0x19
            //   68cb0a0000           | push                0xacb
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   3bde                 | cmp                 ebx, esi

        $sequence_6 = { 52 8b45ec 50 e8???????? 83c40c 50 e8???????? }
            // n = 7, score = 200
            //   52                   | push                edx
            //   8b45ec               | mov                 eax, dword ptr [ebp - 0x14]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { 83c41c ba???????? b9???????? e8???????? 8bf0 85db 7517 }
            // n = 7, score = 200
            //   83c41c               | add                 esp, 0x1c
            //   ba????????           |                     
            //   b9????????           |                     
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   85db                 | test                ebx, ebx
            //   7517                 | jne                 0x19

        $sequence_8 = { 0106 e8???????? 8d4dd8 e8???????? 8d4d08 e8???????? 8d4d14 }
            // n = 7, score = 200
            //   0106                 | add                 dword ptr [esi], eax
            //   e8????????           |                     
            //   8d4dd8               | lea                 ecx, [ebp - 0x28]
            //   e8????????           |                     
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   e8????????           |                     
            //   8d4d14               | lea                 ecx, [ebp + 0x14]

        $sequence_9 = { 68???????? e8???????? 83ec1c c68424b803000062 8bcc 8964244c }
            // n = 6, score = 200
            //   68????????           |                     
            //   e8????????           |                     
            //   83ec1c               | sub                 esp, 0x1c
            //   c68424b803000062     | mov                 byte ptr [esp + 0x3b8], 0x62
            //   8bcc                 | mov                 ecx, esp
            //   8964244c             | mov                 dword ptr [esp + 0x4c], esp

    condition:
        7 of them and filesize < 1974272
}
