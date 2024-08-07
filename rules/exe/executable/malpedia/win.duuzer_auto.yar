rule win_duuzer_auto {

    meta:
        atk_type = "win.duuzer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.duuzer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.duuzer"
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
        $sequence_0 = { 83f804 7408 83c8ff e9???????? }
            // n = 4, score = 200
            //   83f804               | cmp                 eax, 4
            //   7408                 | je                  0xa
            //   83c8ff               | or                  eax, 0xffffffff
            //   e9????????           |                     

        $sequence_1 = { 0145f0 1155f4 85c9 7533 }
            // n = 4, score = 100
            //   0145f0               | add                 dword ptr [ebp - 0x10], eax
            //   1155f4               | adc                 dword ptr [ebp - 0xc], edx
            //   85c9                 | test                ecx, ecx
            //   7533                 | jne                 0x35

        $sequence_2 = { 57 4154 4155 4881ec88080000 488b05???????? 4833c4 }
            // n = 6, score = 100
            //   57                   | dec                 eax
            //   4154                 | sub                 esp, 0x30
            //   4155                 | dec                 eax
            //   4881ec88080000       | mov                 eax, dword ptr [ecx + 0x20]
            //   488b05????????       |                     
            //   4833c4               | xor                 edi, edi

        $sequence_3 = { 00f4 c640001c c740008a460323 d188470383ee }
            // n = 4, score = 100
            //   00f4                 | add                 ah, dh
            //   c640001c             | mov                 byte ptr [eax], 0x1c
            //   c740008a460323       | mov                 dword ptr [eax], 0x2303468a
            //   d188470383ee         | ror                 dword ptr [eax - 0x117cfcb9], 1

        $sequence_4 = { 56 57 b830910000 e8???????? }
            // n = 4, score = 100
            //   56                   | xor                 eax, esp
            //   57                   | push                esi
            //   b830910000           | push                edi
            //   e8????????           |                     

        $sequence_5 = { 56 57 b8a0010100 e8???????? }
            // n = 4, score = 100
            //   56                   | mov                 eax, 0x9130
            //   57                   | dec                 eax
            //   b8a0010100           | sub                 esp, eax
            //   e8????????           |                     

        $sequence_6 = { 56 57 488dac2410fcffff 4881ecf0040000 }
            // n = 4, score = 100
            //   56                   | push                esi
            //   57                   | push                edi
            //   488dac2410fcffff     | dec                 eax
            //   4881ecf0040000       | lea                 ebp, [esp - 0x3f0]

        $sequence_7 = { 01442410 3bfb 75c4 8b4630 }
            // n = 4, score = 100
            //   01442410             | add                 dword ptr [esp + 0x10], eax
            //   3bfb                 | cmp                 edi, ebx
            //   75c4                 | jne                 0xffffffc6
            //   8b4630               | mov                 eax, dword ptr [esi + 0x30]

        $sequence_8 = { 57 4154 4883ec20 448be2 }
            // n = 4, score = 100
            //   57                   | inc                 ecx
            //   4154                 | push                esp
            //   4883ec20             | inc                 ecx
            //   448be2               | push                ebp

        $sequence_9 = { 57 4154 4155 4156 4883ec30 488b05???????? }
            // n = 6, score = 100
            //   57                   | push                edi
            //   4154                 | mov                 eax, 0x101a0
            //   4155                 | push                esi
            //   4156                 | push                edi
            //   4883ec30             | mov                 eax, 0x101a0
            //   488b05????????       |                     

        $sequence_10 = { 014dec 83bf8400000000 7708 398780000000 }
            // n = 4, score = 100
            //   014dec               | add                 dword ptr [ebp - 0x14], ecx
            //   83bf8400000000       | cmp                 dword ptr [edi + 0x84], 0
            //   7708                 | ja                  0xa
            //   398780000000         | cmp                 dword ptr [edi + 0x80], eax

        $sequence_11 = { 57 4154 4155 4883ec20 33f6 488bd9 }
            // n = 6, score = 100
            //   57                   | push                esi
            //   4154                 | dec                 eax
            //   4155                 | lea                 ebp, [esp - 0x37]
            //   4883ec20             | dec                 eax
            //   33f6                 | sub                 esp, 0xf0
            //   488bd9               | push                edi

        $sequence_12 = { 014dec 66837dec00 0f8efc010000 0fbf45ec }
            // n = 4, score = 100
            //   014dec               | add                 dword ptr [ebp - 0x14], ecx
            //   66837dec00           | cmp                 word ptr [ebp - 0x14], 0
            //   0f8efc010000         | jle                 0x202
            //   0fbf45ec             | movsx               eax, word ptr [ebp - 0x14]

        $sequence_13 = { 00e0 3541000436 41 0023 }
            // n = 4, score = 100
            //   00e0                 | add                 al, ah
            //   3541000436           | xor                 eax, 0x36040041
            //   41                   | inc                 ecx
            //   0023                 | add                 byte ptr [ebx], ah

        $sequence_14 = { 010b 014e4c 014e48 014e54 }
            // n = 4, score = 100
            //   010b                 | add                 dword ptr [ebx], ecx
            //   014e4c               | add                 dword ptr [esi + 0x4c], ecx
            //   014e48               | add                 dword ptr [esi + 0x48], ecx
            //   014e54               | add                 dword ptr [esi + 0x54], ecx

    condition:
        7 of them and filesize < 491520
}