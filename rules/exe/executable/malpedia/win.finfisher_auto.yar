rule win_finfisher_auto {

    meta:
        atk_type = "win.finfisher."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.finfisher."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.finfisher"
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
        $sequence_0 = { 68???????? 6804010000 8d85ccf9ffff 50 }
            // n = 4, score = 200
            //   68????????           |                     
            //   6804010000           | push                0x104
            //   8d85ccf9ffff         | lea                 eax, [ebp - 0x634]
            //   50                   | push                eax

        $sequence_1 = { 56 8d85ccf9ffff 50 e8???????? }
            // n = 4, score = 200
            //   56                   | push                esi
            //   8d85ccf9ffff         | lea                 eax, [ebp - 0x634]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_2 = { 6a20 6a03 8d8594f7ffff 50 8d8578f7ffff 50 68000000c0 }
            // n = 7, score = 100
            //   6a20                 | push                0x20
            //   6a03                 | push                3
            //   8d8594f7ffff         | lea                 eax, [ebp - 0x86c]
            //   50                   | push                eax
            //   8d8578f7ffff         | lea                 eax, [ebp - 0x888]
            //   50                   | push                eax
            //   68000000c0           | push                0xc0000000

        $sequence_3 = { 663bc1 7506 8345e404 ebd8 }
            // n = 4, score = 100
            //   663bc1               | cmp                 ax, cx
            //   7506                 | jne                 8
            //   8345e404             | add                 dword ptr [ebp - 0x1c], 4
            //   ebd8                 | jmp                 0xffffffda

        $sequence_4 = { 0f853affffff c785d0fbffffd5d8ffff e9???????? 8b07 83e808 }
            // n = 5, score = 100
            //   0f853affffff         | jne                 0xffffff40
            //   c785d0fbffffd5d8ffff     | mov    dword ptr [ebp - 0x430], 0xffffd8d5
            //   e9????????           |                     
            //   8b07                 | mov                 eax, dword ptr [edi]
            //   83e808               | sub                 eax, 8

        $sequence_5 = { 52 68a0608000 eb11 8b4708 8b4dd4 }
            // n = 5, score = 100
            //   52                   | push                edx
            //   68a0608000           | push                0x8060a0
            //   eb11                 | jmp                 0x13
            //   8b4708               | mov                 eax, dword ptr [edi + 8]
            //   8b4dd4               | mov                 ecx, dword ptr [ebp - 0x2c]

        $sequence_6 = { 397714 7403 56 eb02 6a02 56 50 }
            // n = 7, score = 100
            //   397714               | cmp                 dword ptr [edi + 0x14], esi
            //   7403                 | je                  5
            //   56                   | push                esi
            //   eb02                 | jmp                 4
            //   6a02                 | push                2
            //   56                   | push                esi
            //   50                   | push                eax

        $sequence_7 = { e8???????? 56 e8???????? 8b861c030000 3d10270000 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   56                   | push                esi
            //   e8????????           |                     
            //   8b861c030000         | mov                 eax, dword ptr [esi + 0x31c]
            //   3d10270000           | cmp                 eax, 0x2710

        $sequence_8 = { 56 8d859cf7ffff 50 56 a1???????? }
            // n = 5, score = 100
            //   56                   | push                esi
            //   8d859cf7ffff         | lea                 eax, [ebp - 0x864]
            //   50                   | push                eax
            //   56                   | push                esi
            //   a1????????           |                     

        $sequence_9 = { 85db 7424 8b17 8d448614 8b08 }
            // n = 5, score = 100
            //   85db                 | test                ebx, ebx
            //   7424                 | je                  0x26
            //   8b17                 | mov                 edx, dword ptr [edi]
            //   8d448614             | lea                 eax, [esi + eax*4 + 0x14]
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_10 = { e9???????? 8b859cf7ffff ff7004 ff15???????? 8985c0f7ffff 8b8d9cf7ffff }
            // n = 6, score = 100
            //   e9????????           |                     
            //   8b859cf7ffff         | mov                 eax, dword ptr [ebp - 0x864]
            //   ff7004               | push                dword ptr [eax + 4]
            //   ff15????????         |                     
            //   8985c0f7ffff         | mov                 dword ptr [ebp - 0x840], eax
            //   8b8d9cf7ffff         | mov                 ecx, dword ptr [ebp - 0x864]

        $sequence_11 = { 6a09 ff15???????? 3bc6 7490 8bd0 }
            // n = 5, score = 100
            //   6a09                 | push                9
            //   ff15????????         |                     
            //   3bc6                 | cmp                 eax, esi
            //   7490                 | je                  0xffffff92
            //   8bd0                 | mov                 edx, eax

        $sequence_12 = { ffb5b8f7ffff eb5f 8d8578f7ffff 50 6a01 8d85acf7ffff }
            // n = 6, score = 100
            //   ffb5b8f7ffff         | push                dword ptr [ebp - 0x848]
            //   eb5f                 | jmp                 0x61
            //   8d8578f7ffff         | lea                 eax, [ebp - 0x888]
            //   50                   | push                eax
            //   6a01                 | push                1
            //   8d85acf7ffff         | lea                 eax, [ebp - 0x854]

        $sequence_13 = { 8d85acfbffff 50 53 56 }
            // n = 4, score = 100
            //   8d85acfbffff         | lea                 eax, [ebp - 0x454]
            //   50                   | push                eax
            //   53                   | push                ebx
            //   56                   | push                esi

    condition:
        7 of them and filesize < 262144
}