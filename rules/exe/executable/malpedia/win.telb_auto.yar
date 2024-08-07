rule win_telb_auto {

    meta:
        atk_type = "win.telb."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.telb."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.telb"
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
        $sequence_0 = { c744242400000000 e8???????? 68???????? ff15???????? a3???????? 8d4c2430 6a12 }
            // n = 7, score = 200
            //   c744242400000000     | mov                 dword ptr [esp + 0x24], 0
            //   e8????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     
            //   a3????????           |                     
            //   8d4c2430             | lea                 ecx, [esp + 0x30]
            //   6a12                 | push                0x12

        $sequence_1 = { 68???????? 8d8c24a4000000 e8???????? 8d8c24a0000000 e8???????? 8d8c24a0000000 }
            // n = 6, score = 200
            //   68????????           |                     
            //   8d8c24a4000000       | lea                 ecx, [esp + 0xa4]
            //   e8????????           |                     
            //   8d8c24a0000000       | lea                 ecx, [esp + 0xa0]
            //   e8????????           |                     
            //   8d8c24a0000000       | lea                 ecx, [esp + 0xa0]

        $sequence_2 = { 668908 8d8d68eeffff c645fc26 e8???????? 8d8d68eeffff e8???????? 8d8dd0efffff }
            // n = 7, score = 200
            //   668908               | mov                 word ptr [eax], cx
            //   8d8d68eeffff         | lea                 ecx, [ebp - 0x1198]
            //   c645fc26             | mov                 byte ptr [ebp - 4], 0x26
            //   e8????????           |                     
            //   8d8d68eeffff         | lea                 ecx, [ebp - 0x1198]
            //   e8????????           |                     
            //   8d8dd0efffff         | lea                 ecx, [ebp - 0x1030]

        $sequence_3 = { 8945fc 85f6 7407 83feff 746f eb69 8b1c9d485c4100 }
            // n = 7, score = 200
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   85f6                 | test                esi, esi
            //   7407                 | je                  9
            //   83feff               | cmp                 esi, -1
            //   746f                 | je                  0x71
            //   eb69                 | jmp                 0x6b
            //   8b1c9d485c4100       | mov                 ebx, dword ptr [ebx*4 + 0x415c48]

        $sequence_4 = { 50 e8???????? 8b853ceeffff 83c40c 8985b0efffff 89b5b4efffff c645fc35 }
            // n = 7, score = 200
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b853ceeffff         | mov                 eax, dword ptr [ebp - 0x11c4]
            //   83c40c               | add                 esp, 0xc
            //   8985b0efffff         | mov                 dword ptr [ebp - 0x1050], eax
            //   89b5b4efffff         | mov                 dword ptr [ebp - 0x104c], esi
            //   c645fc35             | mov                 byte ptr [ebp - 4], 0x35

        $sequence_5 = { 8d85f0bfffff 50 ff15???????? 85c0 0f847b020000 6800200000 }
            // n = 6, score = 200
            //   8d85f0bfffff         | lea                 eax, [ebp - 0x4010]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f847b020000         | je                  0x281
            //   6800200000           | push                0x2000

        $sequence_6 = { 0f8796150000 52 51 e8???????? 83c408 807c241200 }
            // n = 6, score = 200
            //   0f8796150000         | ja                  0x159c
            //   52                   | push                edx
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   807c241200           | cmp                 byte ptr [esp + 0x12], 0

        $sequence_7 = { 8d442468 50 e8???????? 837c244408 8d4c2430 }
            // n = 5, score = 200
            //   8d442468             | lea                 eax, [esp + 0x68]
            //   50                   | push                eax
            //   e8????????           |                     
            //   837c244408           | cmp                 dword ptr [esp + 0x44], 8
            //   8d4c2430             | lea                 ecx, [esp + 0x30]

        $sequence_8 = { 0f438570efffff 8d8d88efffff 50 e8???????? 6a01 68???????? 8d8d88efffff }
            // n = 7, score = 200
            //   0f438570efffff       | cmovae              eax, dword ptr [ebp - 0x1090]
            //   8d8d88efffff         | lea                 ecx, [ebp - 0x1078]
            //   50                   | push                eax
            //   e8????????           |                     
            //   6a01                 | push                1
            //   68????????           |                     
            //   8d8d88efffff         | lea                 ecx, [ebp - 0x1078]

        $sequence_9 = { 85f6 0f8551010000 a1???????? b9???????? 83c0f5 50 56 }
            // n = 7, score = 200
            //   85f6                 | test                esi, esi
            //   0f8551010000         | jne                 0x157
            //   a1????????           |                     
            //   b9????????           |                     
            //   83c0f5               | add                 eax, -0xb
            //   50                   | push                eax
            //   56                   | push                esi

    condition:
        7 of them and filesize < 286720
}