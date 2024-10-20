rule win_grabbot_auto {

    meta:
        atk_type = "win.grabbot."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.grabbot."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grabbot"
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
        $sequence_0 = { 0fb702 83f85a 770b 83f841 7206 }
            // n = 5, score = 3300
            //   0fb702               | movzx               eax, word ptr [edx]
            //   83f85a               | cmp                 eax, 0x5a
            //   770b                 | ja                  0xd
            //   83f841               | cmp                 eax, 0x41
            //   7206                 | jb                  8

        $sequence_1 = { 83f85a 770d 83f841 7208 83c020 }
            // n = 5, score = 3300
            //   83f85a               | cmp                 eax, 0x5a
            //   770d                 | ja                  0xf
            //   83f841               | cmp                 eax, 0x41
            //   7208                 | jb                  0xa
            //   83c020               | add                 eax, 0x20

        $sequence_2 = { 83f841 7206 83c020 0fb7c0 83c202 }
            // n = 5, score = 3300
            //   83f841               | cmp                 eax, 0x41
            //   7206                 | jb                  8
            //   83c020               | add                 eax, 0x20
            //   0fb7c0               | movzx               eax, ax
            //   83c202               | add                 edx, 2

        $sequence_3 = { ffd0 c3 b88dbdc13f 50 e8???????? }
            // n = 5, score = 3200
            //   ffd0                 | call                eax
            //   c3                   | ret                 
            //   b88dbdc13f           | mov                 eax, 0x3fc1bd8d
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_4 = { ffe0 c3 c3 c3 68b9be7238 e8???????? 50 }
            // n = 7, score = 3200
            //   ffe0                 | jmp                 eax
            //   c3                   | ret                 
            //   c3                   | ret                 
            //   c3                   | ret                 
            //   68b9be7238           | push                0x3872beb9
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_5 = { 03c7 813850450000 0f853c010000 0fb74804 ba4c010000 }
            // n = 5, score = 3200
            //   03c7                 | add                 eax, edi
            //   813850450000         | cmp                 dword ptr [eax], 0x4550
            //   0f853c010000         | jne                 0x142
            //   0fb74804             | movzx               ecx, word ptr [eax + 4]
            //   ba4c010000           | mov                 edx, 0x14c

        $sequence_6 = { 03c3 813850450000 8945f8 7408 32c0 }
            // n = 5, score = 3200
            //   03c3                 | add                 eax, ebx
            //   813850450000         | cmp                 dword ptr [eax], 0x4550
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   7408                 | je                  0xa
            //   32c0                 | xor                 al, al

        $sequence_7 = { 7523 8b8c18a0000000 85c9 0f8489000000 837c187405 }
            // n = 5, score = 3200
            //   7523                 | jne                 0x25
            //   8b8c18a0000000       | mov                 ecx, dword ptr [eax + ebx + 0xa0]
            //   85c9                 | test                ecx, ecx
            //   0f8489000000         | je                  0x8f
            //   837c187405           | cmp                 dword ptr [eax + ebx + 0x74], 5

        $sequence_8 = { 56 ffd0 33c9 66894c37fe }
            // n = 4, score = 2600
            //   56                   | push                esi
            //   ffd0                 | call                eax
            //   33c9                 | xor                 ecx, ecx
            //   66894c37fe           | mov                 word ptr [edi + esi - 2], cx

        $sequence_9 = { 7428 8b0d???????? 8908 8b0d???????? 894804 }
            // n = 5, score = 2300
            //   7428                 | je                  0x2a
            //   8b0d????????         |                     
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8b0d????????         |                     
            //   894804               | mov                 dword ptr [eax + 4], ecx

        $sequence_10 = { 89480c e9???????? 33c0 e9???????? }
            // n = 4, score = 2300
            //   89480c               | mov                 dword ptr [eax + 0xc], ecx
            //   e9????????           |                     
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     

        $sequence_11 = { 894808 8b0d???????? 89480c e9???????? }
            // n = 4, score = 2300
            //   894808               | mov                 dword ptr [eax + 8], ecx
            //   8b0d????????         |                     
            //   89480c               | mov                 dword ptr [eax + 0xc], ecx
            //   e9????????           |                     

        $sequence_12 = { 8bf0 85f6 741d 8d4601 50 e8???????? }
            // n = 6, score = 2000
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   741d                 | je                  0x1f
            //   8d4601               | lea                 eax, [esi + 1]
            //   50                   | push                eax
            //   e8????????           |                     

        $sequence_13 = { 85c0 56 0f9fc3 e8???????? 83c414 }
            // n = 5, score = 2000
            //   85c0                 | test                eax, eax
            //   56                   | push                esi
            //   0f9fc3               | setg                bl
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14

        $sequence_14 = { ff15???????? a3???????? 85c0 7505 83c8ff }
            // n = 5, score = 2000
            //   ff15????????         |                     
            //   a3????????           |                     
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   83c8ff               | or                  eax, 0xffffffff

        $sequence_15 = { 741b 8d440002 50 e8???????? }
            // n = 4, score = 2000
            //   741b                 | je                  0x1d
            //   8d440002             | lea                 eax, [eax + eax + 2]
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 1335296
}