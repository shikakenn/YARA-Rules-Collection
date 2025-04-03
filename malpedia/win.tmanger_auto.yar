rule win_tmanger_auto {

    meta:
        id = "2RVG0iMHkbe9kfUeED5jDJ"
        fingerprint = "v1_sha256_a7986e1f1ff68dbdf6cb715e7bd380c31c6c5e7bcad1efb5e3857ab5edff19ad"
        version = "1"
        date = "2024-10-31"
        modified = "2025-04-03"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "YARA-RULES-COLLECTION"
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        description = "Detects win.tmanger."
        category = "INFO"
        info = "AUTOGENERATED RULE BROUGHT TO YOU BY YARA-SIGNATOR"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tmanger"
        malpedia_rule_date = "20241030"
        malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
        malpedia_version = "20241030"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    strings:
        $sequence_0 = { c74118d95dc845 c7411cf8f0564e c7412066b8276e c7412425d933d1 c7412861fdc72a c7412cdf9134d2 }
            // n = 6, score = 200
            //   c74118d95dc845       | push                eax
            //   c7411cf8f0564e       | lea                 eax, [ebp - 0x410]
            //   c7412066b8276e       | movq                qword ptr [ebp - 0x32b], xmm0
            //   c7412425d933d1       | push                eax
            //   c7412861fdc72a       | sub                 esp, 0xc
            //   c7412cdf9134d2       | lea                 eax, [esi - 0xf0]

        $sequence_1 = { c741651f013f62 c74169388b8e92 c7416d9b14f6a0 c7417180fcd6bb }
            // n = 4, score = 200
            //   c741651f013f62       | mov                 ecx, 0x14
            //   c74169388b8e92       | call                esi
            //   c7416d9b14f6a0       | test                ax, ax
            //   c7417180fcd6bb       | je                  0x13c

        $sequence_2 = { c74169388b8e92 c7416d9b14f6a0 c7417180fcd6bb c74175d7401d36 c7417958fffa19 }
            // n = 5, score = 200
            //   c74169388b8e92       | dec                 eax
            //   c7416d9b14f6a0       | lea                 eax, [0x12d66]
            //   c7417180fcd6bb       | dec                 eax
            //   c74175d7401d36       | cmp                 dword ptr [edi - 0x10], eax
            //   c7417958fffa19       | je                  0xcc9

        $sequence_3 = { c7410491b20524 c74108cc6188ff c7410c16d9fdf8 c741103a71c135 }
            // n = 4, score = 200
            //   c7410491b20524       | dec                 eax
            //   c74108cc6188ff       | sub                 esp, eax
            //   c7410c16d9fdf8       | push                0
            //   c741103a71c135       | lea                 ecx, [ebp - 0x3c4]

        $sequence_4 = { c7411cf8f0564e c7412066b8276e c7412425d933d1 c7412861fdc72a c7412cdf9134d2 c74130324d251d c74134375ec19d }
            // n = 7, score = 200
            //   c7411cf8f0564e       | push                ebp
            //   c7412066b8276e       | mov                 ebp, esp
            //   c7412425d933d1       | ret                 4
            //   c7412861fdc72a       | mov                 eax, dword ptr [ecx + 0xb0]
            //   c7412cdf9134d2       | cmp                 eax, dword ptr [ecx + 0x9c]
            //   c74130324d251d       | jne                 0x1eec
            //   c74134375ec19d       | test                eax, eax

        $sequence_5 = { c741651f013f62 c74169388b8e92 c7416d9b14f6a0 c7417180fcd6bb c74175d7401d36 c7417958fffa19 }
            // n = 6, score = 200
            //   c741651f013f62       | push                ecx
            //   c74169388b8e92       | push                dword ptr [eax - 0xc]
            //   c7416d9b14f6a0       | lea                 ecx, [ebp - 0x100]
            //   c7417180fcd6bb       | mov                 dword ptr [ebp - 0x100], esi
            //   c74175d7401d36       | mov                 dword ptr [ebp - 0x108], 0x574ebc
            //   c7417958fffa19       | lea                 ecx, [ebp - 0x108]

        $sequence_6 = { c74169388b8e92 c7416d9b14f6a0 c7417180fcd6bb c74175d7401d36 }
            // n = 4, score = 200
            //   c74169388b8e92       | mov                 ecx, 0x18
            //   c7416d9b14f6a0       | dec                 esp
            //   c7417180fcd6bb       | lea                 eax, [0xa2d6]
            //   c74175d7401d36       | dec                 eax

        $sequence_7 = { c74114c2a02ab0 c74118d95dc845 c7411cf8f0564e c7412066b8276e }
            // n = 4, score = 200
            //   c74114c2a02ab0       | mov                 ecx, 0x14
            //   c74118d95dc845       | mov                 ecx, 1
            //   c7411cf8f0564e       | or                  edx, 0xffffffff
            //   c7412066b8276e       | mov                 ecx, 0x80000001

        $sequence_8 = { c741103a71c135 c74114c2a02ab0 c74118d95dc845 c7411cf8f0564e c7412066b8276e c7412425d933d1 c7412861fdc72a }
            // n = 7, score = 200
            //   c741103a71c135       | mov                 edx, dword ptr [ecx + 8]
            //   c74114c2a02ab0       | test                edx, edx
            //   c74118d95dc845       | je                  0x1e7c
            //   c7411cf8f0564e       | mov                 eax, dword ptr [edx]
            //   c7412066b8276e       | push                esi
            //   c7412425d933d1       | push                edx
            //   c7412861fdc72a       | ret                 4

        $sequence_9 = { c7412066b8276e c7412425d933d1 c7412861fdc72a c7412cdf9134d2 }
            // n = 4, score = 200
            //   c7412066b8276e       | test                eax, eax
            //   c7412425d933d1       | mov                 ecx, 0x80000002
            //   c7412861fdc72a       | add                 esp, 0x10
            //   c7412cdf9134d2       | push                0

    condition:
        7 of them and filesize < 8252416
}
