rule win_nitlove_auto {

    meta:
        atk_type = "win.nitlove."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.nitlove."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nitlove"
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
        $sequence_0 = { 8d85c4feffff b902000080 66a5 be???????? 8d7df8 50 8d45f8 }
            // n = 7, score = 200
            //   8d85c4feffff         | lea                 eax, [ebp - 0x13c]
            //   b902000080           | mov                 ecx, 0x80000002
            //   66a5                 | movsw               word ptr es:[edi], word ptr [esi]
            //   be????????           |                     
            //   8d7df8               | lea                 edi, [ebp - 8]
            //   50                   | push                eax
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_1 = { ff15???????? 85c0 74e1 837dfcff }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   74e1                 | je                  0xffffffe3
            //   837dfcff             | cmp                 dword ptr [ebp - 4], -1

        $sequence_2 = { ffd7 8b75f4 8b4df8 8b859cfaffff 8b95a0faffff 83c010 }
            // n = 6, score = 200
            //   ffd7                 | call                edi
            //   8b75f4               | mov                 esi, dword ptr [ebp - 0xc]
            //   8b4df8               | mov                 ecx, dword ptr [ebp - 8]
            //   8b859cfaffff         | mov                 eax, dword ptr [ebp - 0x564]
            //   8b95a0faffff         | mov                 edx, dword ptr [ebp - 0x560]
            //   83c010               | add                 eax, 0x10

        $sequence_3 = { 0f853d010000 6a00 56 baf3b33d04 }
            // n = 4, score = 200
            //   0f853d010000         | jne                 0x143
            //   6a00                 | push                0
            //   56                   | push                esi
            //   baf3b33d04           | mov                 edx, 0x43db3f3

        $sequence_4 = { 8945d8 8b4508 8945c0 8b450c }
            // n = 4, score = 200
            //   8945d8               | mov                 dword ptr [ebp - 0x28], eax
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8945c0               | mov                 dword ptr [ebp - 0x40], eax
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_5 = { e8???????? ffd0 bab2bb282b b9???????? }
            // n = 4, score = 200
            //   e8????????           |                     
            //   ffd0                 | call                eax
            //   bab2bb282b           | mov                 edx, 0x2b28bbb2
            //   b9????????           |                     

        $sequence_6 = { ba7f22fb0e b9???????? e8???????? ffd0 }
            // n = 4, score = 200
            //   ba7f22fb0e           | mov                 edx, 0xefb227f
            //   b9????????           |                     
            //   e8????????           |                     
            //   ffd0                 | call                eax

        $sequence_7 = { 8bcb e8???????? ffd0 ff75fc ba07d457d6 8bcb }
            // n = 6, score = 200
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     
            //   ffd0                 | call                eax
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ba07d457d6           | mov                 edx, 0xd657d407
            //   8bcb                 | mov                 ecx, ebx

        $sequence_8 = { 0f84aa000000 53 56 57 e8???????? e8???????? 8d45f8 }
            // n = 7, score = 200
            //   0f84aa000000         | je                  0xb0
            //   53                   | push                ebx
            //   56                   | push                esi
            //   57                   | push                edi
            //   e8????????           |                     
            //   e8????????           |                     
            //   8d45f8               | lea                 eax, [ebp - 8]

        $sequence_9 = { ffd0 8b4dfc 6a00 8904b1 b9???????? 837dec00 }
            // n = 6, score = 200
            //   ffd0                 | call                eax
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   6a00                 | push                0
            //   8904b1               | mov                 dword ptr [ecx + esi*4], eax
            //   b9????????           |                     
            //   837dec00             | cmp                 dword ptr [ebp - 0x14], 0

    condition:
        7 of them and filesize < 49152
}