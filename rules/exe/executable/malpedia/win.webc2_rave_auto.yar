rule win_webc2_rave_auto {

    meta:
        atk_type = "win.webc2_rave."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.webc2_rave."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_rave"
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
        $sequence_0 = { 0f8454010000 8b35???????? 8d542414 6a00 }
            // n = 4, score = 100
            //   0f8454010000         | je                  0x15a
            //   8b35????????         |                     
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   6a00                 | push                0

        $sequence_1 = { 0f84ea000000 8d542414 6a00 52 8d44241a 6a01 }
            // n = 6, score = 100
            //   0f84ea000000         | je                  0xf0
            //   8d542414             | lea                 edx, [esp + 0x14]
            //   6a00                 | push                0
            //   52                   | push                edx
            //   8d44241a             | lea                 eax, [esp + 0x1a]
            //   6a01                 | push                1

        $sequence_2 = { 56 68???????? 53 52 ffd7 3bc3 894614 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   68????????           |                     
            //   53                   | push                ebx
            //   52                   | push                edx
            //   ffd7                 | call                edi
            //   3bc3                 | cmp                 eax, ebx
            //   894614               | mov                 dword ptr [esi + 0x14], eax

        $sequence_3 = { f7d1 49 3bd9 72e5 }
            // n = 4, score = 100
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx
            //   3bd9                 | cmp                 ebx, ecx
            //   72e5                 | jb                  0xffffffe7

        $sequence_4 = { 8d442418 50 51 e8???????? 85c0 74b1 }
            // n = 6, score = 100
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   74b1                 | je                  0xffffffb3

        $sequence_5 = { 895c2448 ffd7 3bc3 894610 7517 }
            // n = 5, score = 100
            //   895c2448             | mov                 dword ptr [esp + 0x48], ebx
            //   ffd7                 | call                edi
            //   3bc3                 | cmp                 eax, ebx
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   7517                 | jne                 0x19

        $sequence_6 = { 7418 8b742418 46 4f }
            // n = 4, score = 100
            //   7418                 | je                  0x1a
            //   8b742418             | mov                 esi, dword ptr [esp + 0x18]
            //   46                   | inc                 esi
            //   4f                   | dec                 edi

        $sequence_7 = { 33c9 33f6 85ed 7e45 8b942414020000 53 }
            // n = 6, score = 100
            //   33c9                 | xor                 ecx, ecx
            //   33f6                 | xor                 esi, esi
            //   85ed                 | test                ebp, ebp
            //   7e45                 | jle                 0x47
            //   8b942414020000       | mov                 edx, dword ptr [esp + 0x214]
            //   53                   | push                ebx

        $sequence_8 = { 03d1 8bca 894c2414 7872 }
            // n = 4, score = 100
            //   03d1                 | add                 edx, ecx
            //   8bca                 | mov                 ecx, edx
            //   894c2414             | mov                 dword ptr [esp + 0x14], ecx
            //   7872                 | js                  0x74

        $sequence_9 = { e8???????? 83c404 ff15???????? 85ff }
            // n = 4, score = 100
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   ff15????????         |                     
            //   85ff                 | test                edi, edi

    condition:
        7 of them and filesize < 57344
}