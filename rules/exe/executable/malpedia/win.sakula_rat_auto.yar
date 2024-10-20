rule win_sakula_rat_auto {

    meta:
        atk_type = "win.sakula_rat."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sakula_rat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sakula_rat"
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
        $sequence_0 = { 6a00 6800010000 6a00 6a00 68???????? }
            // n = 5, score = 300
            //   6a00                 | xor                 ecx, ecx
            //   6800010000           | dec                 eax
            //   6a00                 | lea                 ecx, [0x1d8a]
            //   6a00                 | xor                 edx, edx
            //   68????????           |                     

        $sequence_1 = { 8bf0 56 6a01 57 53 }
            // n = 5, score = 200
            //   8bf0                 | cmp                 eax, 0
            //   56                   | je                  0x145
            //   6a01                 | push                0
            //   57                   | push                0
            //   53                   | push                dword ptr [ebp - 0x14]

        $sequence_2 = { 57 56 e8???????? 8d7e10 8ad8 57 8bc7 }
            // n = 7, score = 200
            //   57                   | push                esi
            //   56                   | add                 esp, 0x1c
            //   e8????????           |                     
            //   8d7e10               | pop                 edi
            //   8ad8                 | pop                 ebx
            //   57                   | mov                 esi, eax
            //   8bc7                 | push                esi

        $sequence_3 = { 33c9 85f6 7e15 8a0411 84c0 7409 }
            // n = 6, score = 200
            //   33c9                 | push                dword ptr [ebp - 4]
            //   85f6                 | push                0
            //   7e15                 | push                0x100
            //   8a0411               | push                0
            //   84c0                 | push                0
            //   7409                 | push                ebx

        $sequence_4 = { 53 e8???????? 83c40c 6a00 6a00 57 53 }
            // n = 7, score = 200
            //   53                   | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   83c40c               | push                0
            //   6a00                 | push                dword ptr [ebp - 4]
            //   6a00                 | cmp                 eax, 0
            //   57                   | je                  0x6d
            //   53                   | push                0x104

        $sequence_5 = { 8bc7 e8???????? 83c408 833e01 }
            // n = 4, score = 200
            //   8bc7                 | je                  0x5b
            //   e8????????           |                     
            //   83c408               | cmp                 eax, 0
            //   833e01               | push                0x104

        $sequence_6 = { 50 e8???????? 83c404 32c0 5d }
            // n = 5, score = 200
            //   50                   | push                1
            //   e8????????           |                     
            //   83c404               | push                edi
            //   32c0                 | push                ebx
            //   5d                   | mov                 eax, edi

        $sequence_7 = { 53 e8???????? 56 e8???????? 83c41c 5f 5b }
            // n = 7, score = 200
            //   53                   | je                  4
            //   e8????????           |                     
            //   56                   | xor                 eax, eax
            //   e8????????           |                     
            //   83c41c               | push                eax
            //   5f                   | push                dword ptr [ebp - 4]
            //   5b                   | mov                 dword ptr [ebp - 0x1c], eax

        $sequence_8 = { 66895db0 48895c2450 4889442458 4889442460 }
            // n = 4, score = 100
            //   66895db0             | cmp                 eax, esi
            //   48895c2450           | je                  0x1f
            //   4889442458           | dec                 eax
            //   4889442460           | mov                 ecx, dword ptr [ebp - 0x39]

        $sequence_9 = { ff15???????? 33d2 488bcb ff15???????? e8???????? 33c9 ff15???????? }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   33d2                 | dec                 eax
            //   488bcb               | and                 dword ptr [esp + 0x30], 0
            //   ff15????????         |                     
            //   e8????????           |                     
            //   33c9                 | xor                 edx, edx
            //   ff15????????         |                     

        $sequence_10 = { 8b45d8 8b5de0 01d8 8945e0 6a01 e8???????? }
            // n = 6, score = 100
            //   8b45d8               | dec                 eax
            //   8b5de0               | mov                 dword ptr [esp + 0x50], ebx
            //   01d8                 | dec                 eax
            //   8945e0               | mov                 dword ptr [esp + 0x58], eax
            //   6a01                 | dec                 eax
            //   e8????????           |                     

        $sequence_11 = { 4c8bc6 33d2 33c9 448bc8 897c2428 48895c2420 ff15???????? }
            // n = 7, score = 100
            //   4c8bc6               | dec                 esp
            //   33d2                 | mov                 eax, esi
            //   33c9                 | xor                 edx, edx
            //   448bc8               | xor                 ecx, ecx
            //   897c2428             | inc                 esp
            //   48895c2420           | mov                 ecx, eax
            //   ff15????????         |                     

        $sequence_12 = { 0f8516010000 488d15e61c0000 41b804010000 48890d???????? ff15???????? ff15???????? 83f801 }
            // n = 7, score = 100
            //   0f8516010000         | cmp                 eax, esi
            //   488d15e61c0000       | je                  0x61
            //   41b804010000         | dec                 esp
            //   48890d????????       |                     
            //   ff15????????         |                     
            //   ff15????????         |                     
            //   83f801               | lea                 ecx, [ebp - 0x31]

        $sequence_13 = { 7459 68???????? 68???????? e8???????? 83f800 }
            // n = 5, score = 100
            //   7459                 | push                dword ptr [ebp - 0xc]
            //   68????????           |                     
            //   68????????           |                     
            //   e8????????           |                     
            //   83f800               | pop                 eax

        $sequence_14 = { 8945e4 83f800 0f843c010000 6a00 6a00 ff75ec }
            // n = 6, score = 100
            //   8945e4               | lea                 edx, [0x1152]
            //   83f800               | push                0
            //   0f843c010000         | push                0x100
            //   6a00                 | push                0
            //   6a00                 | push                0
            //   ff75ec               | push                eax

        $sequence_15 = { e8???????? 50 ff75f4 e8???????? 58 eb02 31c0 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   50                   | cmp                 eax, esi
            //   ff75f4               | je                  0x65
            //   e8????????           |                     
            //   58                   | dec                 esp
            //   eb02                 | lea                 ecx, [ebp - 0x31]
            //   31c0                 | mov                 word ptr [ebp - 0x50], bx

        $sequence_16 = { 8a03 3c00 7414 b21a }
            // n = 4, score = 100
            //   8a03                 | mov                 dword ptr [esp + 0x60], eax
            //   3c00                 | dec                 eax
            //   7414                 | mov                 dword ptr [esp + 0x58], eax
            //   b21a                 | dec                 eax

        $sequence_17 = { ff15???????? 33d2 488d4deb 448d426c }
            // n = 4, score = 100
            //   ff15????????         |                     
            //   33d2                 | mov                 eax, 0x104
            //   488d4deb             | cmp                 eax, 1
            //   448d426c             | dec                 eax

        $sequence_18 = { ff15???????? 488bce 488bd8 ff15???????? 488364243800 488364243000 }
            // n = 6, score = 100
            //   ff15????????         |                     
            //   488bce               | jne                 0x11c
            //   488bd8               | dec                 eax
            //   ff15????????         |                     
            //   488364243800         | lea                 edx, [0x1ce6]
            //   488364243000         | inc                 ecx

        $sequence_19 = { e9???????? 31c0 7402 31c0 50 ff75fc e8???????? }
            // n = 7, score = 100
            //   e9????????           |                     
            //   31c0                 | mov                 dword ptr [esp + 0x60], eax
            //   7402                 | mov                 word ptr [ebp - 0x20], bx
            //   31c0                 | dec                 esp
            //   50                   | lea                 eax, [0x1fe9]
            //   ff75fc               | dec                 eax
            //   e8????????           |                     

        $sequence_20 = { ff9080000000 3bc6 741b 488b4dc7 488b01 }
            // n = 5, score = 100
            //   ff9080000000         | mov                 ecx, esi
            //   3bc6                 | dec                 eax
            //   741b                 | mov                 ebx, eax
            //   488b4dc7             | dec                 eax
            //   488b01               | and                 dword ptr [esp + 0x38], 0

        $sequence_21 = { 6804010000 ff75fc 6a00 e8???????? ff75fc }
            // n = 5, score = 100
            //   6804010000           | jmp                 8
            //   ff75fc               | xor                 eax, eax
            //   6a00                 | mov                 eax, dword ptr [ebp - 0x28]
            //   e8????????           |                     
            //   ff75fc               | mov                 ebx, dword ptr [ebp - 0x20]

        $sequence_22 = { 33d2 ff15???????? 3bc6 745f 4c8d4dcf }
            // n = 5, score = 100
            //   33d2                 | mov                 dword ptr [esp + 0x28], edi
            //   ff15????????         |                     
            //   3bc6                 | dec                 eax
            //   745f                 | mov                 dword ptr [esp + 0x20], ebx
            //   4c8d4dcf             | xor                 edx, edx

    condition:
        7 of them and filesize < 229376
}