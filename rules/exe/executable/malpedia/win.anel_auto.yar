rule win_anel_auto {

    meta:
        atk_type = "win.anel."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.anel."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anel"
        malpedia_rule_date = "20231130"
        malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
        malpedia_version = "20230808"
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { f7fe 43 3bd8 7621 8bd0 d1ea be91cfba01 }
            // n = 7, score = 200
            //   f7fe                 | idiv                esi
            //   43                   | inc                 ebx
            //   3bd8                 | cmp                 ebx, eax
            //   7621                 | jbe                 0x23
            //   8bd0                 | mov                 edx, eax
            //   d1ea                 | shr                 edx, 1
            //   be91cfba01           | mov                 esi, 0x1bacf91

        $sequence_1 = { eb24 8bca 83e910 3b5904 7f17 7c07 }
            // n = 6, score = 200
            //   eb24                 | jmp                 0x26
            //   8bca                 | mov                 ecx, edx
            //   83e910               | sub                 ecx, 0x10
            //   3b5904               | cmp                 ebx, dword ptr [ecx + 4]
            //   7f17                 | jg                  0x19
            //   7c07                 | jl                  9

        $sequence_2 = { 8bf9 2bf8 85c0 7411 eb03 83c010 3bc1 }
            // n = 7, score = 200
            //   8bf9                 | mov                 edi, ecx
            //   2bf8                 | sub                 edi, eax
            //   85c0                 | test                eax, eax
            //   7411                 | je                  0x13
            //   eb03                 | jmp                 5
            //   83c010               | add                 eax, 0x10
            //   3bc1                 | cmp                 eax, ecx

        $sequence_3 = { c645fc06 e8???????? c645fc07 8bc8 c645fc08 e8???????? 8bc6 }
            // n = 7, score = 200
            //   c645fc06             | mov                 byte ptr [ebp - 4], 6
            //   e8????????           |                     
            //   c645fc07             | mov                 byte ptr [ebp - 4], 7
            //   8bc8                 | mov                 ecx, eax
            //   c645fc08             | mov                 byte ptr [ebp - 4], 8
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi

        $sequence_4 = { 897814 895810 89458c 8818 8d4678 }
            // n = 5, score = 200
            //   897814               | mov                 dword ptr [eax + 0x14], edi
            //   895810               | mov                 dword ptr [eax + 0x10], ebx
            //   89458c               | mov                 dword ptr [ebp - 0x74], eax
            //   8818                 | mov                 byte ptr [eax], bl
            //   8d4678               | lea                 eax, [esi + 0x78]

        $sequence_5 = { c1e704 037d08 a5 a5 a5 a5 5f }
            // n = 7, score = 200
            //   c1e704               | shl                 edi, 4
            //   037d08               | add                 edi, dword ptr [ebp + 8]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   5f                   | pop                 edi

        $sequence_6 = { 53 33ff c645fc00 e8???????? 837d1c08 8b4508 7303 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   33ff                 | xor                 edi, edi
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0
            //   e8????????           |                     
            //   837d1c08             | cmp                 dword ptr [ebp + 0x1c], 8
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   7303                 | jae                 5

        $sequence_7 = { 8bec 51 56 8bf0 33c0 894610 c746140f000000 }
            // n = 7, score = 200
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   33c0                 | xor                 eax, eax
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   c746140f000000       | mov                 dword ptr [esi + 0x14], 0xf

        $sequence_8 = { 8d8bd0000000 50 8d55d8 c645fc01 e8???????? 6a01 33ff }
            // n = 7, score = 200
            //   8d8bd0000000         | lea                 ecx, [ebx + 0xd0]
            //   50                   | push                eax
            //   8d55d8               | lea                 edx, [ebp - 0x28]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   6a01                 | push                1
            //   33ff                 | xor                 edi, edi

        $sequence_9 = { e8???????? 8bd6 8d8dc8feffff c645fc01 e8???????? c645fc02 83bd04ffffff05 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   8bd6                 | mov                 edx, esi
            //   8d8dc8feffff         | lea                 ecx, [ebp - 0x138]
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   e8????????           |                     
            //   c645fc02             | mov                 byte ptr [ebp - 4], 2
            //   83bd04ffffff05       | cmp                 dword ptr [ebp - 0xfc], 5

    condition:
        7 of them and filesize < 376832
}