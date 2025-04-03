rule win_nitol_auto {

    meta:
        id = "38dGSG13HSzCv34sSL0APy"
        fingerprint = "v1_sha256_f965a0fe296415280cef677cfeda82c56822d9b36e24511179288d488384a005"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.nitol."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nitol"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 6a28 8d8540ffffff 50 e8???????? 83c440 668945f6 8d45ec }
            // n = 7, score = 200
            //   6a28                 | push                0x28
            //   8d8540ffffff         | lea                 eax, [ebp - 0xc0]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c440               | add                 esp, 0x40
            //   668945f6             | mov                 word ptr [ebp - 0xa], ax
            //   8d45ec               | lea                 eax, [ebp - 0x14]

        $sequence_1 = { 57 56 68???????? 57 57 ffd5 68e8030000 }
            // n = 7, score = 200
            //   57                   | push                edi
            //   56                   | push                esi
            //   68????????           |                     
            //   57                   | push                edi
            //   57                   | push                edi
            //   ffd5                 | call                ebp
            //   68e8030000           | push                0x3e8

        $sequence_2 = { 3bc5 89442410 750e ffd7 99 b9e8030000 }
            // n = 6, score = 200
            //   3bc5                 | cmp                 eax, ebp
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   750e                 | jne                 0x10
            //   ffd7                 | call                edi
            //   99                   | cdq                 
            //   b9e8030000           | mov                 ecx, 0x3e8

        $sequence_3 = { 50 e8???????? 59 40 50 8d8568faffff 50 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   40                   | inc                 eax
            //   50                   | push                eax
            //   8d8568faffff         | lea                 eax, [ebp - 0x598]
            //   50                   | push                eax

        $sequence_4 = { 33db 39be88000000 0f8ee5000000 57 57 56 68???????? }
            // n = 7, score = 200
            //   33db                 | xor                 ebx, ebx
            //   39be88000000         | cmp                 dword ptr [esi + 0x88], edi
            //   0f8ee5000000         | jle                 0xeb
            //   57                   | push                edi
            //   57                   | push                edi
            //   56                   | push                esi
            //   68????????           |                     

        $sequence_5 = { 8d85e8faffff 50 ff15???????? 83c418 833d????????01 744a ff75e8 }
            // n = 7, score = 200
            //   8d85e8faffff         | lea                 eax, [ebp - 0x518]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c418               | add                 esp, 0x18
            //   833d????????01       |                     
            //   744a                 | je                  0x4c
            //   ff75e8               | push                dword ptr [ebp - 0x18]

        $sequence_6 = { 0f86d5030000 6a4b 50 e8???????? 8d8588f4ffff 50 e8???????? }
            // n = 7, score = 200
            //   0f86d5030000         | jbe                 0x3db
            //   6a4b                 | push                0x4b
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d8588f4ffff         | lea                 eax, [ebp - 0xb78]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_7 = { 50 ff15???????? 668365f600 6800010000 e8???????? 83c41c 8845f4 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   ff15????????         |                     
            //   668365f600           | and                 word ptr [ebp - 0xa], 0
            //   6800010000           | push                0x100
            //   e8????????           |                     
            //   83c41c               | add                 esp, 0x1c
            //   8845f4               | mov                 byte ptr [ebp - 0xc], al

        $sequence_8 = { c645ed11 ff15???????? 8945f0 8d852cffffff 50 e8???????? 8945f4 }
            // n = 7, score = 200
            //   c645ed11             | mov                 byte ptr [ebp - 0x13], 0x11
            //   ff15????????         |                     
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   8d852cffffff         | lea                 eax, [ebp - 0xd4]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax

        $sequence_9 = { ffd6 668945d6 8d45cc 6a0c 50 8d8540ffffff }
            // n = 6, score = 200
            //   ffd6                 | call                esi
            //   668945d6             | mov                 word ptr [ebp - 0x2a], ax
            //   8d45cc               | lea                 eax, [ebp - 0x34]
            //   6a0c                 | push                0xc
            //   50                   | push                eax
            //   8d8540ffffff         | lea                 eax, [ebp - 0xc0]

    condition:
        7 of them and filesize < 139264
}
