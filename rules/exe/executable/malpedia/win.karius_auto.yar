rule win_karius_auto {

    meta:
        atk_type = "win.karius."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.karius."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.karius"
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
        $sequence_0 = { 4c8b8424a0000000 bf01000000 8bd7 498bce ffd3 4183bf8c00000000 }
            // n = 6, score = 400
            //   4c8b8424a0000000     | je                  0xc1
            //   bf01000000           | inc                 ebp
            //   8bd7                 | mov                 ebx, dword ptr [edi + 0x88]
            //   498bce               | dec                 ebp
            //   ffd3                 | add                 ebx, esi
            //   4183bf8c00000000     | inc                 ecx

        $sequence_1 = { 4d03d6 448bcd 85db 0f8477000000 8bb424b0000000 }
            // n = 5, score = 400
            //   4d03d6               | mov                 edx, dword ptr [ebx + 0x24]
            //   448bcd               | xor                 ebp, ebp
            //   85db                 | dec                 ebp
            //   0f8477000000         | add                 eax, esi
            //   8bb424b0000000       | dec                 ebp

        $sequence_2 = { 0f84b3000000 458b9f88000000 4d03de 418b5b18 85db }
            // n = 5, score = 400
            //   0f84b3000000         | inc                 esp
            //   458b9f88000000       | mov                 ecx, ebp
            //   4d03de               | test                ebx, ebx
            //   418b5b18             | je                  0x7f
            //   85db                 | mov                 esi, dword ptr [esp + 0xb0]

        $sequence_3 = { ffd3 4183bf8c00000000 0f84b3000000 458b9f88000000 }
            // n = 4, score = 400
            //   ffd3                 | call                ebx
            //   4183bf8c00000000     | inc                 ecx
            //   0f84b3000000         | cmp                 dword ptr [edi + 0x8c], 0
            //   458b9f88000000       | je                  0xb9

        $sequence_4 = { 488b05???????? 4885c0 7512 ff15???????? 488905???????? }
            // n = 5, score = 400
            //   488b05????????       |                     
            //   4885c0               | mov                 ebx, dword ptr [edi + 0x88]
            //   7512                 | inc                 ecx
            //   ff15????????         |                     
            //   488905????????       |                     

        $sequence_5 = { 8bb424b0000000 418b10 8bcd 4903d6 0fb602 }
            // n = 5, score = 400
            //   8bb424b0000000       | add                 edx, esi
            //   418b10               | dec                 ebp
            //   8bcd                 | add                 edx, esi
            //   4903d6               | inc                 esp
            //   0fb602               | mov                 ecx, ebp

        $sequence_6 = { c3 85c0 7505 e8???????? b801000000 }
            // n = 5, score = 400
            //   c3                   | dec                 esp
            //   85c0                 | mov                 ebp, eax
            //   7505                 | dec                 ecx
            //   e8????????           |                     
            //   b801000000           | mov                 ecx, esi

        $sequence_7 = { 85db 0f849d000000 41837b1400 0f8492000000 }
            // n = 4, score = 400
            //   85db                 | mov                 ebx, dword ptr [ebx + 0x18]
            //   0f849d000000         | test                ebx, ebx
            //   41837b1400           | dec                 esp
            //   0f8492000000         | mov                 eax, dword ptr [esp + 0xa0]

        $sequence_8 = { 0f8492000000 458b4320 458b5324 33ed 4d03c6 4d03d6 }
            // n = 6, score = 400
            //   0f8492000000         | inc                 ebp
            //   458b4320             | mov                 ebx, dword ptr [edi + 0x88]
            //   458b5324             | je                  0x98
            //   33ed                 | inc                 ebp
            //   4d03c6               | mov                 eax, dword ptr [ebx + 0x20]
            //   4d03d6               | inc                 ebp

        $sequence_9 = { 8d7b01 448bfb 448be3 4885c9 }
            // n = 4, score = 300
            //   8d7b01               | inc                 ecx
            //   448bfb               | mov                 edx, dword ptr [eax]
            //   448be3               | inc                 esp
            //   4885c9               | mov                 ecx, ebp

        $sequence_10 = { 56 be???????? 33d2 8a040a 3a06 7522 }
            // n = 6, score = 300
            //   56                   | dec                 ebp
            //   be????????           |                     
            //   33d2                 | test                ebp, ebp
            //   8a040a               | xor                 edx, edx
            //   3a06                 | dec                 eax
            //   7522                 | mov                 ecx, esi

        $sequence_11 = { 83e830 89450c db450c 8a07 d9ca d8c9 }
            // n = 6, score = 300
            //   83e830               | mov                 edx, edi
            //   89450c               | dec                 ecx
            //   db450c               | mov                 ecx, esi
            //   8a07                 | call                ebx
            //   d9ca                 | inc                 ecx
            //   d8c9                 | cmp                 dword ptr [edi + 0x8c], 0

        $sequence_12 = { b801000000 8702 83f801 74f4 }
            // n = 4, score = 300
            //   b801000000           | dec                 esp
            //   8702                 | mov                 ebp, eax
            //   83f801               | dec                 ecx
            //   74f4                 | mov                 ecx, esi

        $sequence_13 = { 752c 8a4701 3c30 7c25 3c39 }
            // n = 5, score = 300
            //   752c                 | mov                 ecx, esp
            //   8a4701               | dec                 ebp
            //   3c30                 | mov                 eax, edi
            //   7c25                 | dec                 eax
            //   3c39                 | mov                 edx, eax

        $sequence_14 = { 488d4b10 488d542450 41b804000000 c6430f68 }
            // n = 4, score = 300
            //   488d4b10             | xor                 ebp, ebp
            //   488d542450           | inc                 ecx
            //   41b804000000         | mov                 ebx, dword ptr [ebx + 0x18]
            //   c6430f68             | test                ebx, ebx

        $sequence_15 = { 4d8bcf 33d2 41b800001000 488bce }
            // n = 4, score = 300
            //   4d8bcf               | mov                 ecx, ebp
            //   33d2                 | dec                 ecx
            //   41b800001000         | add                 edx, esi
            //   488bce               | movzx               eax, byte ptr [edx]

        $sequence_16 = { 803e5d 7508 5f 5b 8d4601 5e }
            // n = 6, score = 300
            //   803e5d               | dec                 ecx
            //   7508                 | mov                 ecx, esi
            //   5f                   | dec                 ebp
            //   5b                   | test                ebp, ebp
            //   8d4601               | lea                 edi, [ebx + 1]
            //   5e                   | inc                 esp

        $sequence_17 = { 7505 8d7b02 eb09 6685c0 }
            // n = 4, score = 300
            //   7505                 | cmp                 dword ptr [edi + 0x8c], 0
            //   8d7b02               | je                  0xc6
            //   eb09                 | inc                 ebp
            //   6685c0               | mov                 ebx, dword ptr [edi + 0x88]

        $sequence_18 = { 8d7308 56 ffd7 50 56 e8???????? }
            // n = 6, score = 300
            //   8d7308               | dec                 esp
            //   56                   | mov                 esi, eax
            //   ffd7                 | dec                 eax
            //   50                   | test                eax, eax
            //   56                   | dec                 ebp
            //   e8????????           |                     

        $sequence_19 = { ff15???????? 4c8be8 498bce ff15???????? 4d85ed }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   4c8be8               | mov                 eax, dword ptr [ebx + 0x20]
            //   498bce               | je                  0xb9
            //   ff15????????         |                     
            //   4d85ed               | inc                 ebp

        $sequence_20 = { 8b4dfc 83c404 8945f4 83c706 050024ffff }
            // n = 5, score = 300
            //   8b4dfc               | dec                 eax
            //   83c404               | mov                 ecx, esi
            //   8945f4               | test                eax, eax
            //   83c706               | dec                 esp
            //   050024ffff           | mov                 ebp, eax

        $sequence_21 = { 4d8bc7 488bd0 488bce ff15???????? }
            // n = 4, score = 300
            //   4d8bc7               | mov                 edx, dword ptr [eax]
            //   488bd0               | mov                 ecx, ebp
            //   488bce               | dec                 ecx
            //   ff15????????         |                     

        $sequence_22 = { e9???????? 8b45f8 5f 5b 5e }
            // n = 5, score = 300
            //   e9????????           |                     
            //   8b45f8               | je                  0xc8
            //   5f                   | inc                 ebp
            //   5b                   | mov                 ebx, dword ptr [edi + 0x88]
            //   5e                   | dec                 ebp

        $sequence_23 = { 8b4508 85c0 7417 8b4008 85c0 7412 8b4d0c }
            // n = 7, score = 300
            //   8b4508               | jne                 0x2a
            //   85c0                 | inc                 ecx
            //   7417                 | mov                 ebx, dword ptr [ebx + 0x18]
            //   8b4008               | test                ebx, ebx
            //   85c0                 | je                  0xa9
            //   7412                 | inc                 ecx
            //   8b4d0c               | cmp                 dword ptr [ebx + 0x14], 0

        $sequence_24 = { 7405 f60001 7502 33c0 }
            // n = 4, score = 300
            //   7405                 | dec                 ebp
            //   f60001               | test                ebp, ebp
            //   7502                 | dec                 eax
            //   33c0                 | mov                 ecx, eax

        $sequence_25 = { 448bc0 33d2 488bce ff15???????? 4c8bf0 4885c0 }
            // n = 6, score = 300
            //   448bc0               | nop                 dword ptr [eax + eax]
            //   33d2                 | dec                 ebp
            //   488bce               | add                 edx, esi
            //   ff15????????         |                     
            //   4c8bf0               | inc                 esp
            //   4885c0               | mov                 ecx, ebp

        $sequence_26 = { 48895c2420 4d8bcc 4d8bc7 488bd0 }
            // n = 4, score = 300
            //   48895c2420           | add                 edx, esi
            //   4d8bcc               | je                  0xa3
            //   4d8bc7               | inc                 ecx
            //   488bd0               | cmp                 dword ptr [ebx + 0x14], 0

    condition:
        7 of them and filesize < 434176
}