rule win_remexi_auto {

    meta:
        atk_type = "win.remexi."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.remexi."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.remexi"
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
        $sequence_0 = { 56 c706ffffffff e8???????? 83c404 }
            // n = 4, score = 300
            //   56                   | push                esi
            //   c706ffffffff         | mov                 dword ptr [esi], 0xffffffff
            //   e8????????           |                     
            //   83c404               | add                 esp, 4

        $sequence_1 = { 53 50 ff15???????? 3dffffff00 }
            // n = 4, score = 200
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   3dffffff00           | cmp                 eax, 0xffffff

        $sequence_2 = { ff15???????? 8bf0 85f6 7513 8b45d8 }
            // n = 5, score = 200
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   85f6                 | test                esi, esi
            //   7513                 | jne                 0x15
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]

        $sequence_3 = { 68???????? 50 ff15???????? 8b0d???????? 8b35???????? 890d???????? 68???????? }
            // n = 7, score = 200
            //   68????????           |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b0d????????         |                     
            //   8b35????????         |                     
            //   890d????????         |                     
            //   68????????           |                     

        $sequence_4 = { 8945e0 8945e4 8945e8 b802000000 }
            // n = 4, score = 200
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   8945e4               | mov                 dword ptr [ebp - 0x1c], eax
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   b802000000           | mov                 eax, 2

        $sequence_5 = { ff15???????? 6a10 8d4ddc 8bf0 51 56 ff15???????? }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   6a10                 | push                0x10
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]
            //   8bf0                 | mov                 esi, eax
            //   51                   | push                ecx
            //   56                   | push                esi
            //   ff15????????         |                     

        $sequence_6 = { 8b95d4feffff 52 6a00 68ffff1f00 ffd7 }
            // n = 5, score = 200
            //   8b95d4feffff         | mov                 edx, dword ptr [ebp - 0x12c]
            //   52                   | push                edx
            //   6a00                 | push                0
            //   68ffff1f00           | push                0x1fffff
            //   ffd7                 | call                edi

        $sequence_7 = { e8???????? 83ec1c 8bcc 89642430 6aff 53 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   83ec1c               | sub                 esp, 0x1c
            //   8bcc                 | mov                 ecx, esp
            //   89642430             | mov                 dword ptr [esp + 0x30], esp
            //   6aff                 | push                -1
            //   53                   | push                ebx

        $sequence_8 = { 52 56 50 e8???????? 8bf0 eb02 }
            // n = 6, score = 200
            //   52                   | push                edx
            //   56                   | push                esi
            //   50                   | push                eax
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   eb02                 | jmp                 4

        $sequence_9 = { 57 e8???????? 6a01 6a00 6a00 ff15???????? }
            // n = 6, score = 200
            //   57                   | push                edi
            //   e8????????           |                     
            //   6a01                 | push                1
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_10 = { 33c0 5f c3 56 ff15???????? 57 8b3d???????? }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   5f                   | pop                 edi
            //   c3                   | ret                 
            //   56                   | push                esi
            //   ff15????????         |                     
            //   57                   | push                edi
            //   8b3d????????         |                     

        $sequence_11 = { 8b45d8 8b4818 8b5104 50 8955e0 }
            // n = 5, score = 200
            //   8b45d8               | mov                 eax, dword ptr [ebp - 0x28]
            //   8b4818               | mov                 ecx, dword ptr [eax + 0x18]
            //   8b5104               | mov                 edx, dword ptr [ecx + 4]
            //   50                   | push                eax
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx

        $sequence_12 = { 890d???????? 68???????? 41 50 a3???????? }
            // n = 5, score = 200
            //   890d????????         |                     
            //   68????????           |                     
            //   41                   | inc                 ecx
            //   50                   | push                eax
            //   a3????????           |                     

        $sequence_13 = { 488bf9 33d2 33c9 e8???????? 488d0d74e90100 4885c0 480f44c1 }
            // n = 7, score = 100
            //   488bf9               | mov                 ecx, 0x9020102
            //   33d2                 | nop                 
            //   33c9                 | dec                 eax
            //   e8????????           |                     
            //   488d0d74e90100       | cmp                 dword ptr [ebx + 0x18], 0x10
            //   4885c0               | dec                 eax
            //   480f44c1             | lea                 edx, [0x273fe]

        $sequence_14 = { 488d15fe730200 488d4c2450 e8???????? 90 41b902000000 }
            // n = 5, score = 100
            //   488d15fe730200       | mov                 byte ptr [ebx], 0
            //   488d4c2450           | mov                 eax, edi
            //   e8????????           |                     
            //   90                   | dec                 eax
            //   41b902000000         | mov                 ecx, dword ptr [esp + 0x38]

        $sequence_15 = { 0f8333010000 488d4550 483bf0 0f8726010000 }
            // n = 4, score = 100
            //   0f8333010000         | xor                 ecx, ecx
            //   488d4550             | dec                 eax
            //   483bf0               | lea                 ecx, [0x1e974]
            //   0f8726010000         | dec                 eax

        $sequence_16 = { 488b0b e8???????? 48c743180f000000 48c7431000000000 c60300 8bc7 488b4c2438 }
            // n = 7, score = 100
            //   488b0b               | dec                 eax
            //   e8????????           |                     
            //   48c743180f000000     | and                 dword ptr [ecx + 0x470], 0
            //   48c7431000000000     | mov                 ecx, 0xd
            //   c60300               | dec                 eax
            //   8bc7                 | mov                 ecx, dword ptr [ebx]
            //   488b4c2438           | dec                 eax

        $sequence_17 = { 4883ec40 48c7442428feffffff 48895c2460 4889742468 488b05???????? }
            // n = 5, score = 100
            //   4883ec40             | dec                 eax
            //   48c7442428feffffff     | lea    ecx, [esp + 0x50]
            //   48895c2460           | nop                 
            //   4889742468           | inc                 ecx
            //   488b05????????       |                     

        $sequence_18 = { 488d0527dd0100 488981b8000000 4883a17004000000 b90d000000 }
            // n = 4, score = 100
            //   488d0527dd0100       | dec                 eax
            //   488981b8000000       | lea                 eax, [0x1dd27]
            //   4883a17004000000     | dec                 eax
            //   b90d000000           | mov                 dword ptr [ecx + 0xb8], eax

        $sequence_19 = { 488d4c2470 e8???????? 85c0 750a b902020208 }
            // n = 5, score = 100
            //   488d4c2470           | mov                 ecx, 2
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   750a                 | mov                 edi, ecx
            //   b902020208           | xor                 edx, edx

        $sequence_20 = { b902010209 e8???????? 90 48837b1810 }
            // n = 4, score = 100
            //   b902010209           | mov                 dword ptr [ebx + 0x18], 0xf
            //   e8????????           |                     
            //   90                   | dec                 eax
            //   48837b1810           | mov                 dword ptr [ebx + 0x10], 0

    condition:
        7 of them and filesize < 614400
}