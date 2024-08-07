rule win_funny_dream_auto {

    meta:
        atk_type = "win.funny_dream."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.funny_dream."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.funny_dream"
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
        $sequence_0 = { c785e0ddffff01000000 50 6880000000 68ffff0000 ffb3c0000000 }
            // n = 5, score = 300
            //   c785e0ddffff01000000     | mov    dword ptr [ebp - 0x2220], 1
            //   50                   | push                eax
            //   6880000000           | push                0x80
            //   68ffff0000           | push                0xffff
            //   ffb3c0000000         | push                dword ptr [ebx + 0xc0]

        $sequence_1 = { 6a00 ff7728 ffd6 6a00 ff7724 ff15???????? 8b4714 }
            // n = 7, score = 300
            //   6a00                 | push                0
            //   ff7728               | push                dword ptr [edi + 0x28]
            //   ffd6                 | call                esi
            //   6a00                 | push                0
            //   ff7724               | push                dword ptr [edi + 0x24]
            //   ff15????????         |                     
            //   8b4714               | mov                 eax, dword ptr [edi + 0x14]

        $sequence_2 = { c745d45368656c 50 53 c745d86c457865 c745dc63757465 66c745e04100 }
            // n = 6, score = 300
            //   c745d45368656c       | mov                 dword ptr [ebp - 0x2c], 0x6c656853
            //   50                   | push                eax
            //   53                   | push                ebx
            //   c745d86c457865       | mov                 dword ptr [ebp - 0x28], 0x6578456c
            //   c745dc63757465       | mov                 dword ptr [ebp - 0x24], 0x65747563
            //   66c745e04100         | mov                 word ptr [ebp - 0x20], 0x41

        $sequence_3 = { 85c0 0f8494000000 33c9 8a840d3cffffff }
            // n = 4, score = 300
            //   85c0                 | test                eax, eax
            //   0f8494000000         | je                  0x9a
            //   33c9                 | xor                 ecx, ecx
            //   8a840d3cffffff       | mov                 al, byte ptr [ebp + ecx - 0xc4]

        $sequence_4 = { ff15???????? 85c0 0f85e7feffff 8d4704 899da0fdffff }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   0f85e7feffff         | jne                 0xfffffeed
            //   8d4704               | lea                 eax, [edi + 4]
            //   899da0fdffff         | mov                 dword ptr [ebp - 0x260], ebx

        $sequence_5 = { 6a00 6800040000 8d842458030000 50 }
            // n = 4, score = 300
            //   6a00                 | push                0
            //   6800040000           | push                0x400
            //   8d842458030000       | lea                 eax, [esp + 0x358]
            //   50                   | push                eax

        $sequence_6 = { 50 57 ff15???????? 85c0 7523 8b4618 8b3d???????? }
            // n = 7, score = 300
            //   50                   | push                eax
            //   57                   | push                edi
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7523                 | jne                 0x25
            //   8b4618               | mov                 eax, dword ptr [esi + 0x18]
            //   8b3d????????         |                     

        $sequence_7 = { 50 ff15???????? 8d442408 c744240810000000 50 8d442414 0f57c0 }
            // n = 7, score = 300
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d442408             | lea                 eax, [esp + 8]
            //   c744240810000000     | mov                 dword ptr [esp + 8], 0x10
            //   50                   | push                eax
            //   8d442414             | lea                 eax, [esp + 0x14]
            //   0f57c0               | xorps               xmm0, xmm0

        $sequence_8 = { 85c0 0f84f8000000 68???????? 50 ff15???????? }
            // n = 5, score = 300
            //   85c0                 | test                eax, eax
            //   0f84f8000000         | je                  0xfe
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     

        $sequence_9 = { 83c404 8b4f04 85c9 7504 33c0 eb05 8b4708 }
            // n = 7, score = 300
            //   83c404               | add                 esp, 4
            //   8b4f04               | mov                 ecx, dword ptr [edi + 4]
            //   85c9                 | test                ecx, ecx
            //   7504                 | jne                 6
            //   33c0                 | xor                 eax, eax
            //   eb05                 | jmp                 7
            //   8b4708               | mov                 eax, dword ptr [edi + 8]

    condition:
        7 of them and filesize < 393216
}