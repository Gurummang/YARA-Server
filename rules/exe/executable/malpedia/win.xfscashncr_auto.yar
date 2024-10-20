rule win_xfscashncr_auto {

    meta:
        atk_type = "win.xfscashncr."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.xfscashncr."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xfscashncr"
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
        $sequence_0 = { 0fb6c8 85c9 744e 8b4d10 e8???????? 0fb730 8b8d54ffffff }
            // n = 7, score = 100
            //   0fb6c8               | movzx               ecx, al
            //   85c9                 | test                ecx, ecx
            //   744e                 | je                  0x50
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   e8????????           |                     
            //   0fb730               | movzx               esi, word ptr [eax]
            //   8b8d54ffffff         | mov                 ecx, dword ptr [ebp - 0xac]

        $sequence_1 = { 50 8b4de8 8b5110 52 6a00 682d010000 8b45e8 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8b4de8               | mov                 ecx, dword ptr [ebp - 0x18]
            //   8b5110               | mov                 edx, dword ptr [ecx + 0x10]
            //   52                   | push                edx
            //   6a00                 | push                0
            //   682d010000           | push                0x12d
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]

        $sequence_2 = { 898518feffff 8b8d18feffff 898d14feffff c745fc00000000 8b9514feffff 52 e8???????? }
            // n = 7, score = 100
            //   898518feffff         | mov                 dword ptr [ebp - 0x1e8], eax
            //   8b8d18feffff         | mov                 ecx, dword ptr [ebp - 0x1e8]
            //   898d14feffff         | mov                 dword ptr [ebp - 0x1ec], ecx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   8b9514feffff         | mov                 edx, dword ptr [ebp - 0x1ec]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_3 = { 686b070000 68???????? 8b4508 50 e8???????? 83c40c 8b4508 }
            // n = 7, score = 100
            //   686b070000           | push                0x76b
            //   68????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_4 = { 8b4de4 66891401 0fb755f4 81fa00800000 7f27 0fb745f4 3d00800000 }
            // n = 7, score = 100
            //   8b4de4               | mov                 ecx, dword ptr [ebp - 0x1c]
            //   66891401             | mov                 word ptr [ecx + eax], dx
            //   0fb755f4             | movzx               edx, word ptr [ebp - 0xc]
            //   81fa00800000         | cmp                 edx, 0x8000
            //   7f27                 | jg                  0x29
            //   0fb745f4             | movzx               eax, word ptr [ebp - 0xc]
            //   3d00800000           | cmp                 eax, 0x8000

        $sequence_5 = { 83c418 8b08 8b5004 894d10 895514 c78564ffffff00000000 eb35 }
            // n = 7, score = 100
            //   83c418               | add                 esp, 0x18
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b5004               | mov                 edx, dword ptr [eax + 4]
            //   894d10               | mov                 dword ptr [ebp + 0x10], ecx
            //   895514               | mov                 dword ptr [ebp + 0x14], edx
            //   c78564ffffff00000000     | mov    dword ptr [ebp - 0x9c], 0
            //   eb35                 | jmp                 0x37

        $sequence_6 = { e8???????? 0fb6d0 85d2 7557 837de802 750f 8b4520 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   0fb6d0               | movzx               edx, al
            //   85d2                 | test                edx, edx
            //   7557                 | jne                 0x59
            //   837de802             | cmp                 dword ptr [ebp - 0x18], 2
            //   750f                 | jne                 0x11
            //   8b4520               | mov                 eax, dword ptr [ebp + 0x20]

        $sequence_7 = { 837d0800 744a b801000000 85c0 7441 8b4508 83c008 }
            // n = 7, score = 100
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   744a                 | je                  0x4c
            //   b801000000           | mov                 eax, 1
            //   85c0                 | test                eax, eax
            //   7441                 | je                  0x43
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   83c008               | add                 eax, 8

        $sequence_8 = { 8b4d08 d9ee d95c81fc 8b55f0 8b4508 d90490 d9ee }
            // n = 7, score = 100
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   d9ee                 | fldz                
            //   d95c81fc             | fstp                dword ptr [ecx + eax*4 - 4]
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   d90490               | fld                 dword ptr [eax + edx*4]
            //   d9ee                 | fldz                

        $sequence_9 = { 8b5508 83e21f c1e206 8b048dc0195700 0fbe4c1004 81e17fffffff 8b5508 }
            // n = 7, score = 100
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   83e21f               | and                 edx, 0x1f
            //   c1e206               | shl                 edx, 6
            //   8b048dc0195700       | mov                 eax, dword ptr [ecx*4 + 0x5719c0]
            //   0fbe4c1004           | movsx               ecx, byte ptr [eax + edx + 4]
            //   81e17fffffff         | and                 ecx, 0xffffff7f
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 3126272
}