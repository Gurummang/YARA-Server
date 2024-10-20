rule win_teleport_auto {

    meta:
        atk_type = "win.teleport."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.teleport."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.teleport"
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
        $sequence_0 = { 50 8945fc 68???????? c745f001000000 }
            // n = 4, score = 100
            //   50                   | push                eax
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   68????????           |                     
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1

        $sequence_1 = { 57 8bfa 897de8 89b7a0000000 8b4104 8987a4000000 8b5108 }
            // n = 7, score = 100
            //   57                   | push                edi
            //   8bfa                 | mov                 edi, edx
            //   897de8               | mov                 dword ptr [ebp - 0x18], edi
            //   89b7a0000000         | mov                 dword ptr [edi + 0xa0], esi
            //   8b4104               | mov                 eax, dword ptr [ecx + 4]
            //   8987a4000000         | mov                 dword ptr [edi + 0xa4], eax
            //   8b5108               | mov                 edx, dword ptr [ecx + 8]

        $sequence_2 = { 8806 46 89b504ffffff 8b8d04ffffff 0fb6f0 8d85f8feffff 56 }
            // n = 7, score = 100
            //   8806                 | mov                 byte ptr [esi], al
            //   46                   | inc                 esi
            //   89b504ffffff         | mov                 dword ptr [ebp - 0xfc], esi
            //   8b8d04ffffff         | mov                 ecx, dword ptr [ebp - 0xfc]
            //   0fb6f0               | movzx               esi, al
            //   8d85f8feffff         | lea                 eax, [ebp - 0x108]
            //   56                   | push                esi

        $sequence_3 = { c685effeffff00 50 6a00 6a00 c785e0feffff14000000 c785e4feffff00000000 c785f0feffff01000000 }
            // n = 7, score = 100
            //   c685effeffff00       | mov                 byte ptr [ebp - 0x111], 0
            //   50                   | push                eax
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   c785e0feffff14000000     | mov    dword ptr [ebp - 0x120], 0x14
            //   c785e4feffff00000000     | mov    dword ptr [ebp - 0x11c], 0
            //   c785f0feffff01000000     | mov    dword ptr [ebp - 0x110], 1

        $sequence_4 = { 8d8d80f7ffff 899d68f7ffff e8???????? 83cb08 f6c304 740e }
            // n = 6, score = 100
            //   8d8d80f7ffff         | lea                 ecx, [ebp - 0x880]
            //   899d68f7ffff         | mov                 dword ptr [ebp - 0x898], ebx
            //   e8????????           |                     
            //   83cb08               | or                  ebx, 8
            //   f6c304               | test                bl, 4
            //   740e                 | je                  0x10

        $sequence_5 = { 8b35???????? 6a28 85f6 7451 c78560f7ffff80b54200 e8???????? 898584f7ffff }
            // n = 7, score = 100
            //   8b35????????         |                     
            //   6a28                 | push                0x28
            //   85f6                 | test                esi, esi
            //   7451                 | je                  0x53
            //   c78560f7ffff80b54200     | mov    dword ptr [ebp - 0x8a0], 0x42b580
            //   e8????????           |                     
            //   898584f7ffff         | mov                 dword ptr [ebp - 0x87c], eax

        $sequence_6 = { 668945a8 eb17 837e3408 8d4620 c7401000000000 7202 8b00 }
            // n = 7, score = 100
            //   668945a8             | mov                 word ptr [ebp - 0x58], ax
            //   eb17                 | jmp                 0x19
            //   837e3408             | cmp                 dword ptr [esi + 0x34], 8
            //   8d4620               | lea                 eax, [esi + 0x20]
            //   c7401000000000       | mov                 dword ptr [eax + 0x10], 0
            //   7202                 | jb                  4
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_7 = { 330c8560c24200 0fb6c2 330c8560b64200 8bc3 c1e810 894de0 898f94000000 }
            // n = 7, score = 100
            //   330c8560c24200       | xor                 ecx, dword ptr [eax*4 + 0x42c260]
            //   0fb6c2               | movzx               eax, dl
            //   330c8560b64200       | xor                 ecx, dword ptr [eax*4 + 0x42b660]
            //   8bc3                 | mov                 eax, ebx
            //   c1e810               | shr                 eax, 0x10
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   898f94000000         | mov                 dword ptr [edi + 0x94], ecx

        $sequence_8 = { 1bc0 83c801 85c0 0f8400010000 b8???????? 8d8d60fdffff 6690 }
            // n = 7, score = 100
            //   1bc0                 | sbb                 eax, eax
            //   83c801               | or                  eax, 1
            //   85c0                 | test                eax, eax
            //   0f8400010000         | je                  0x106
            //   b8????????           |                     
            //   8d8d60fdffff         | lea                 ecx, [ebp - 0x2a0]
            //   6690                 | nop                 

        $sequence_9 = { 894110 7208 8b09 898d74ffffff 8d0436 50 }
            // n = 6, score = 100
            //   894110               | mov                 dword ptr [ecx + 0x10], eax
            //   7208                 | jb                  0xa
            //   8b09                 | mov                 ecx, dword ptr [ecx]
            //   898d74ffffff         | mov                 dword ptr [ebp - 0x8c], ecx
            //   8d0436               | lea                 eax, [esi + esi]
            //   50                   | push                eax

    condition:
        7 of them and filesize < 458752
}