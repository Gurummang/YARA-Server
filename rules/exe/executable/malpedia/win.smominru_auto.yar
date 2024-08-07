rule win_smominru_auto {

    meta:
        atk_type = "win.smominru."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.smominru."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smominru"
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
        $sequence_0 = { 8b474c 894610 8b4750 894614 8b4754 894618 }
            // n = 6, score = 100
            //   8b474c               | mov                 eax, dword ptr [edi + 0x4c]
            //   894610               | mov                 dword ptr [esi + 0x10], eax
            //   8b4750               | mov                 eax, dword ptr [edi + 0x50]
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   8b4754               | mov                 eax, dword ptr [edi + 0x54]
            //   894618               | mov                 dword ptr [esi + 0x18], eax

        $sequence_1 = { 0fb7c0 8d4dac 51 50 6a01 }
            // n = 5, score = 100
            //   0fb7c0               | movzx               eax, ax
            //   8d4dac               | lea                 ecx, [ebp - 0x54]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   6a01                 | push                1

        $sequence_2 = { 8bd8 eb06 3b4628 0f94c3 }
            // n = 4, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   eb06                 | jmp                 8
            //   3b4628               | cmp                 eax, dword ptr [esi + 0x28]
            //   0f94c3               | sete                bl

        $sequence_3 = { 0f84694ac17b f6c140 0f856f4ac17b 8ad1 80e23f }
            // n = 5, score = 100
            //   0f84694ac17b         | je                  0x7bc14a6f
            //   f6c140               | test                cl, 0x40
            //   0f856f4ac17b         | jne                 0x7bc14a75
            //   8ad1                 | mov                 dl, cl
            //   80e23f               | and                 dl, 0x3f

        $sequence_4 = { 8bd8 eb06 47 ff4df0 }
            // n = 4, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   eb06                 | jmp                 8
            //   47                   | inc                 edi
            //   ff4df0               | dec                 dword ptr [ebp - 0x10]

        $sequence_5 = { 8bd8 eb02 b301 8bc7 }
            // n = 4, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   eb02                 | jmp                 4
            //   b301                 | mov                 bl, 1
            //   8bc7                 | mov                 eax, edi

        $sequence_6 = { 8bd8 eb06 ff45f0 4f }
            // n = 4, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   eb06                 | jmp                 8
            //   ff45f0               | inc                 dword ptr [ebp - 0x10]
            //   4f                   | dec                 edi

        $sequence_7 = { 8bd8 eb02 33db 837dfc00 }
            // n = 4, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   eb02                 | jmp                 4
            //   33db                 | xor                 ebx, ebx
            //   837dfc00             | cmp                 dword ptr [ebp - 4], 0

        $sequence_8 = { 6aff e8???????? 85c0 0f8c05e5c07b }
            // n = 4, score = 100
            //   6aff                 | push                -1
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f8c05e5c07b         | jl                  0x7bc0e50b

        $sequence_9 = { ff15???????? 3d03010000 0f8447a0b17b 85c0 0f8c3fa0b17b }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   3d03010000           | cmp                 eax, 0x103
            //   0f8447a0b17b         | je                  0x7bb1a04d
            //   85c0                 | test                eax, eax
            //   0f8c3fa0b17b         | jl                  0x7bb1a045

        $sequence_10 = { 8b37 8975e0 85f6 0f842bfebb7b 83feff 0f8422febb7b 8b5f14 }
            // n = 7, score = 100
            //   8b37                 | mov                 esi, dword ptr [edi]
            //   8975e0               | mov                 dword ptr [ebp - 0x20], esi
            //   85f6                 | test                esi, esi
            //   0f842bfebb7b         | je                  0x7bbbfe31
            //   83feff               | cmp                 esi, -1
            //   0f8422febb7b         | je                  0x7bbbfe28
            //   8b5f14               | mov                 ebx, dword ptr [edi + 0x14]

        $sequence_11 = { 8bd8 eb09 55 e8???????? 59 }
            // n = 5, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   eb09                 | jmp                 0xb
            //   55                   | push                ebp
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_12 = { 0f8c21f7b07b 0fbe75f4 6bf630 e8???????? 8b402c 648b0d18000000 56 }
            // n = 7, score = 100
            //   0f8c21f7b07b         | jl                  0x7bb0f727
            //   0fbe75f4             | movsx               esi, byte ptr [ebp - 0xc]
            //   6bf630               | imul                esi, esi, 0x30
            //   e8????????           |                     
            //   8b402c               | mov                 eax, dword ptr [eax + 0x2c]
            //   648b0d18000000       | mov                 ecx, dword ptr fs:[0x18]
            //   56                   | push                esi

        $sequence_13 = { 0f8c79feab7b 8d45c4 50 e8???????? 8b45f0 }
            // n = 5, score = 100
            //   0f8c79feab7b         | jl                  0x7babfe7f
            //   8d45c4               | lea                 eax, [ebp - 0x3c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]

        $sequence_14 = { 8bd8 e9???????? 8d4df8 8bd7 8bc6 e8???????? 8d4df4 }
            // n = 7, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   e9????????           |                     
            //   8d4df8               | lea                 ecx, [ebp - 8]
            //   8bd7                 | mov                 edx, edi
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     
            //   8d4df4               | lea                 ecx, [ebp - 0xc]

        $sequence_15 = { 8bd8 eb0a 8d45f0 e8???????? }
            // n = 4, score = 100
            //   8bd8                 | mov                 ebx, eax
            //   eb0a                 | jmp                 0xc
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   e8????????           |                     

    condition:
        7 of them and filesize < 8167424
}