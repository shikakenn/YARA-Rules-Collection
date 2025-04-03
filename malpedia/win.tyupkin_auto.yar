rule win_tyupkin_auto {

    meta:
        id = "Zh9ulYbcGxF2sNqginrnq"
        fingerprint = "v1_sha256_3fdf678ba3f2215f3bc3c4cb4fcafa2e63fdc3ed86ee934af78e8a2b1ca4b6c1"
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
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tyupkin"
        malpedia_rule_date = "20201014"
        malpedia_hash = "a7e3bd57eaf12bf3ea29a863c041091ba3af9ac9"
        malpedia_version = "20201014"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { ff25???????? 55 8bec 81ec28030000 a3???????? 890d???????? }
            // n = 6, score = 200
            //   ff25????????         |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec28030000         | sub                 esp, 0x328
            //   a3????????           |                     
            //   890d????????         |                     

        $sequence_1 = { 68???????? e8???????? 83c418 c3 ff25???????? }
            // n = 5, score = 200
            //   68????????           |                     
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   c3                   | ret                 
            //   ff25????????         |                     

        $sequence_2 = { ff25???????? 55 8bec 81ec28030000 a3???????? 890d???????? 8915???????? }
            // n = 7, score = 200
            //   ff25????????         |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec28030000         | sub                 esp, 0x328
            //   a3????????           |                     
            //   890d????????         |                     
            //   8915????????         |                     

        $sequence_3 = { e8???????? 83c418 c3 ff25???????? 3b0d???????? }
            // n = 5, score = 200
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   c3                   | ret                 
            //   ff25????????         |                     
            //   3b0d????????         |                     

        $sequence_4 = { e8???????? 83c418 c3 ff25???????? }
            // n = 4, score = 200
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   c3                   | ret                 
            //   ff25????????         |                     

        $sequence_5 = { ff25???????? 55 8bec 81ec28030000 a3???????? }
            // n = 5, score = 200
            //   ff25????????         |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec28030000         | sub                 esp, 0x328
            //   a3????????           |                     

        $sequence_6 = { 68???????? 68???????? e8???????? 83c418 c3 ff25???????? }
            // n = 6, score = 200
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   c3                   | ret                 
            //   ff25????????         |                     

        $sequence_7 = { 68???????? e8???????? 83c418 c3 ff25???????? 3b0d???????? 7502 }
            // n = 7, score = 200
            //   68????????           |                     
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   c3                   | ret                 
            //   ff25????????         |                     
            //   3b0d????????         |                     
            //   7502                 | jne                 4

        $sequence_8 = { 83c418 c3 ff25???????? 3b0d???????? 7502 }
            // n = 5, score = 200
            //   83c418               | add                 esp, 0x18
            //   c3                   | ret                 
            //   ff25????????         |                     
            //   3b0d????????         |                     
            //   7502                 | jne                 4

        $sequence_9 = { 83c418 c3 ff25???????? 3b0d???????? }
            // n = 4, score = 200
            //   83c418               | add                 esp, 0x18
            //   c3                   | ret                 
            //   ff25????????         |                     
            //   3b0d????????         |                     

    condition:
        7 of them and filesize < 253952
}
