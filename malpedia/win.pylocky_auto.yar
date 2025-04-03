rule win_pylocky_auto {

    meta:
        id = "74hwzP9TgqTyDm81GmEG3D"
        fingerprint = "v1_sha256_a4b22ff06bf3de9c0ac371c2887cc47ec2f202b93f2abb7dd9ef80970cf85d46"
        version = "1"
        date = "2020-10-14"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "autogenerated rule brought to you by yara-signator"
        category = "INFO"
        tool = "yara-signator v0.5.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pylocky"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 8bc2 c1e818 331c8588224200 0fb6c2 }
            // n = 4, score = 100
            //   8bc2                 | mov                 eax, edx
            //   c1e818               | shr                 eax, 0x18
            //   331c8588224200       | xor                 ebx, dword ptr [eax*4 + 0x422288]
            //   0fb6c2               | movzx               eax, dl

        $sequence_1 = { 0f84e8000000 8d442410 50 ff15???????? 83c404 }
            // n = 5, score = 100
            //   0f84e8000000         | je                  0xee
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   83c404               | add                 esp, 4

        $sequence_2 = { 8944241c 6800100000 56 e8???????? 83c410 }
            // n = 5, score = 100
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   6800100000           | push                0x1000
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10

        $sequence_3 = { 57 8db8e8a34300 57 ff15???????? ff0d???????? 83ef18 83ee01 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8db8e8a34300         | lea                 edi, [eax + 0x43a3e8]
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff0d????????         |                     
            //   83ef18               | sub                 edi, 0x18
            //   83ee01               | sub                 esi, 1

        $sequence_4 = { e8???????? 83c408 85c0 75b6 56 57 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   85c0                 | test                eax, eax
            //   75b6                 | jne                 0xffffffb8
            //   56                   | push                esi
            //   57                   | push                edi
            //   e8????????           |                     

        $sequence_5 = { 83e63f c1f806 6bce30 8945f4 8b048510a14300 894df0 }
            // n = 6, score = 100
            //   83e63f               | and                 esi, 0x3f
            //   c1f806               | sar                 eax, 6
            //   6bce30               | imul                ecx, esi, 0x30
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b048510a14300       | mov                 eax, dword ptr [eax*4 + 0x43a110]
            //   894df0               | mov                 dword ptr [ebp - 0x10], ecx

        $sequence_6 = { 894634 85c0 7505 8bc7 }
            // n = 4, score = 100
            //   894634               | mov                 dword ptr [esi + 0x34], eax
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   8bc7                 | mov                 eax, edi

        $sequence_7 = { ff75f4 56 e8???????? 83c40c 57 e8???????? 59 }
            // n = 7, score = 100
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   56                   | push                esi
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   57                   | push                edi
            //   e8????????           |                     
            //   59                   | pop                 ecx

    condition:
        7 of them and filesize < 626688
}
