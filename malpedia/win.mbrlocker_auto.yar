rule win_mbrlocker_auto {

    meta:
        id = "7LvEwXNlJSAE3fu40j0Iuv"
        fingerprint = "v1_sha256_2abe677d378843746aa6479444a4219927906b009fff2766ade4f081783dbae6"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.mbrlocker."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mbrlocker"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { 50 8b35???????? 8b3d???????? 6a10 68???????? }
            // n = 5, score = 100
            //   50                   | push                eax
            //   8b35????????         |                     
            //   8b3d????????         |                     
            //   6a10                 | push                0x10
            //   68????????           |                     

        $sequence_1 = { 68fe000000 68???????? ffd7 83c408 }
            // n = 4, score = 100
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   83c408               | add                 esp, 8

        $sequence_2 = { 68ac000000 68???????? e8???????? 68ac000000 68???????? ffd7 83c408 }
            // n = 7, score = 100
            //   68ac000000           | push                0xac
            //   68????????           |                     
            //   e8????????           |                     
            //   68ac000000           | push                0xac
            //   68????????           |                     
            //   ffd7                 | call                edi
            //   83c408               | add                 esp, 8

        $sequence_3 = { c705????????ba514000 c705????????00020000 68fe000000 68???????? ffd6 83c408 68ff000000 }
            // n = 7, score = 100
            //   c705????????ba514000     |     
            //   c705????????00020000     |     
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   ffd6                 | call                esi
            //   83c408               | add                 esp, 8
            //   68ff000000           | push                0xff

        $sequence_4 = { 68ac000000 68???????? e8???????? e8???????? }
            // n = 4, score = 100
            //   68ac000000           | push                0xac
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     

        $sequence_5 = { 68ff000000 68ac000000 68???????? e8???????? e8???????? 68ff000000 68ac000000 }
            // n = 7, score = 100
            //   68ff000000           | push                0xff
            //   68ac000000           | push                0xac
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   68ff000000           | push                0xff
            //   68ac000000           | push                0xac

        $sequence_6 = { ac 30c8 aa 4a 75f9 61 c9 }
            // n = 7, score = 100
            //   ac                   | lodsb               al, byte ptr [esi]
            //   30c8                 | xor                 al, cl
            //   aa                   | stosb               byte ptr es:[edi], al
            //   4a                   | dec                 edx
            //   75f9                 | jne                 0xfffffffb
            //   61                   | popal               
            //   c9                   | leave               

        $sequence_7 = { 68fe000000 68???????? e8???????? 68fe000000 }
            // n = 4, score = 100
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   e8????????           |                     
            //   68fe000000           | push                0xfe

        $sequence_8 = { 68fe000000 68???????? e8???????? e8???????? 68ff000000 68fe000000 }
            // n = 6, score = 100
            //   68fe000000           | push                0xfe
            //   68????????           |                     
            //   e8????????           |                     
            //   e8????????           |                     
            //   68ff000000           | push                0xff
            //   68fe000000           | push                0xfe

        $sequence_9 = { 31c8 e8???????? 68ac000000 68???????? }
            // n = 4, score = 100
            //   31c8                 | xor                 eax, ecx
            //   e8????????           |                     
            //   68ac000000           | push                0xac
            //   68????????           |                     

    condition:
        7 of them and filesize < 43008
}
