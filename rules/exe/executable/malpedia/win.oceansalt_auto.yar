rule win_oceansalt_auto {

    meta:
        atk_type = "win.oceansalt."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.oceansalt."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oceansalt"
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
        $sequence_0 = { ff15???????? 6a00 6a02 83f81f }
            // n = 4, score = 300
            //   ff15????????         |                     
            //   6a00                 | mov                 eax, dword ptr [ebx]
            //   6a02                 | dec                 eax
            //   83f81f               | test                eax, eax

        $sequence_1 = { 8d95fcfbffff 6800020000 52 e8???????? 83c410 8d85ecfbffff }
            // n = 6, score = 300
            //   8d95fcfbffff         | push                0
            //   6800020000           | push                edx
            //   52                   | mov                 byte ptr [ebp - 0x404], 0
            //   e8????????           |                     
            //   83c410               | lea                 eax, [ebp - 0x10c]
            //   8d85ecfbffff         | push                eax

        $sequence_2 = { 8d85f4feffff 50 56 ffd7 6a00 }
            // n = 5, score = 300
            //   8d85f4feffff         | je                  0x1a5
            //   50                   | dec                 eax
            //   56                   | lea                 edi, [0x7094]
            //   ffd7                 | jmp                 0x10
            //   6a00                 | dec                 eax

        $sequence_3 = { 6a00 52 c685fcfbffff00 e8???????? }
            // n = 4, score = 300
            //   6a00                 | mov                 esi, eax
            //   52                   | dec                 eax
            //   c685fcfbffff00       | test                eax, eax
            //   e8????????           |                     

        $sequence_4 = { 8b7508 33c0 50 8945f5 668945f9 8845fb 6a07 }
            // n = 7, score = 300
            //   8b7508               | mov                 eax, dword ptr [ecx*8 + 0x40f02c]
            //   33c0                 | mov                 dword ptr [ebp - 4], eax
            //   50                   | push                esi
            //   8945f5               | push                edi
            //   668945f9             | push                0
            //   8845fb               | push                2
            //   6a07                 | mov                 dword ptr [ebp - 0x234], 0x128

        $sequence_5 = { 8945fc 56 57 6a00 6a02 c785ccfdffff28010000 e8???????? }
            // n = 7, score = 300
            //   8945fc               | inc                 ecx
            //   56                   | cmp                 dword ptr [ebp], 0xe06d7363
            //   57                   | jne                 0x32
            //   6a00                 | je                  0x2a
            //   6a02                 | dec                 eax
            //   c785ccfdffff28010000     | lea    ecx, [0x1193e]
            //   e8????????           |                     

        $sequence_6 = { 6a0d 58 5d c3 8b04cd2cf04000 }
            // n = 5, score = 300
            //   6a0d                 | je                  0xc
            //   58                   | call                eax
            //   5d                   | dec                 eax
            //   c3                   | add                 ebx, 8
            //   8b04cd2cf04000       | jle                 0x75

        $sequence_7 = { 56 c645f400 ff15???????? 6a00 6a07 8d4df4 }
            // n = 6, score = 300
            //   56                   | cmp                 eax, 0x1f
            //   c645f400             | push                0xd
            //   ff15????????         |                     
            //   6a00                 | pop                 eax
            //   6a07                 | pop                 ebp
            //   8d4df4               | ret                 

        $sequence_8 = { 4885c0 7419 488d1573750000 488bc8 ff15???????? }
            // n = 5, score = 100
            //   4885c0               | mov                 dword ptr [esp + 0x20], 3
            //   7419                 | dec                 eax
            //   488d1573750000       | mov                 ebx, eax
            //   488bc8               | dec                 eax
            //   ff15????????         |                     

        $sequence_9 = { b903000000 f3a6 0f8463010000 33c9 0fb6840c8c000000 }
            // n = 5, score = 100
            //   b903000000           | inc                 ecx
            //   f3a6                 | mov                 eax, 0x12a
            //   0f8463010000         | mov                 word ptr [esp + 0x40], ax
            //   33c9                 | mov                 ebp, eax
            //   0fb6840c8c000000     | xor                 eax, eax

        $sequence_10 = { 33d2 41b82a010000 6689442440 e8???????? ff15???????? 8be8 }
            // n = 6, score = 100
            //   33d2                 | cmp                 eax, -1
            //   41b82a010000         | dec                 eax
            //   6689442440           | test                eax, eax
            //   e8????????           |                     
            //   ff15????????         |                     
            //   8be8                 | je                  0x1e

        $sequence_11 = { 33c0 e9???????? 48895c2408 4c63c1 488d1d1d890000 4d8bc8 }
            // n = 6, score = 100
            //   33c0                 | dec                 eax
            //   e9????????           |                     
            //   48895c2408           | lea                 edx, [0x7573]
            //   4c63c1               | dec                 eax
            //   488d1d1d890000       | mov                 ecx, eax
            //   4d8bc8               | xor                 edx, edx

        $sequence_12 = { 0f85d0000000 488d0d6b380000 ff15???????? 488bf0 4885c0 0f848c010000 }
            // n = 6, score = 100
            //   0f85d0000000         | dec                 eax
            //   488d0d6b380000       | mov                 dword ptr [esp + 8], ebx
            //   ff15????????         |                     
            //   488bf0               | dec                 esp
            //   4885c0               | arpl                cx, ax
            //   0f848c010000         | dec                 eax

        $sequence_13 = { 488bc8 c744242800000008 c744242003000000 ff15???????? 488bd8 4883f8ff }
            // n = 6, score = 100
            //   488bc8               | inc                 ecx
            //   c744242800000008     | mov                 eax, 0x168
            //   c744242003000000     | dec                 eax
            //   ff15????????         |                     
            //   488bd8               | mov                 ecx, eax
            //   4883f8ff             | mov                 dword ptr [esp + 0x28], 0x8000000

        $sequence_14 = { f3a6 749a 488d8c24b0030000 33d2 41b868010000 e8???????? }
            // n = 6, score = 100
            //   f3a6                 | repe cmpsb          byte ptr [esi], byte ptr es:[edi]
            //   749a                 | je                  0xffffff9c
            //   488d8c24b0030000     | dec                 eax
            //   33d2                 | lea                 ecx, [esp + 0x3b0]
            //   41b868010000         | xor                 edx, edx
            //   e8????????           |                     

        $sequence_15 = { 488d3d94700000 eb0e 488b03 4885c0 7402 ffd0 4883c308 }
            // n = 7, score = 100
            //   488d3d94700000       | lea                 ebx, [0x891d]
            //   eb0e                 | dec                 ebp
            //   488b03               | mov                 ecx, eax
            //   4885c0               | mov                 ecx, 3
            //   7402                 | repe cmpsb          byte ptr [esi], byte ptr es:[edi]
            //   ffd0                 | je                  0x170
            //   4883c308             | xor                 ecx, ecx

    condition:
        7 of them and filesize < 212992
}