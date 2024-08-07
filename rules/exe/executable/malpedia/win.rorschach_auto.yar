rule win_rorschach_auto {

    meta:
        atk_type = "win.rorschach."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rorschach."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rorschach"
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
        $sequence_0 = { 33d2 488d8df8020000 e8???????? 88850e030000 b26e 488d8df8020000 e8???????? }
            // n = 7, score = 100
            //   33d2                 | mov                 byte ptr [ebp + 0x195], al
            //   488d8df8020000       | xor                 edx, edx
            //   e8????????           |                     
            //   88850e030000         | dec                 eax
            //   b26e                 | lea                 ecx, [ebp + 0x180]
            //   488d8df8020000       | mov                 byte ptr [ebp + 0x196], al
            //   e8????????           |                     

        $sequence_1 = { f65d7f 488d15ece30000 4c8d05e9e30000 488955df 488d05d2e30000 488955e7 488945bf }
            // n = 7, score = 100
            //   f65d7f               | mov                 edx, 0xe
            //   488d15ece30000       | dec                 eax
            //   4c8d05e9e30000       | lea                 ecx, [ebp - 0x17]
            //   488955df             | mov                 byte ptr [eax], 0
            //   488d05d2e30000       | mov                 edx, 0xf
            //   488955e7             | dec                 ecx
            //   488945bf             | cmp                 edi, 0x10

        $sequence_2 = { f5 66d3f7 66c1f703 d3d7 4801e3 d2f0 c0f807 }
            // n = 7, score = 100
            //   f5                   | dec                 ecx
            //   66d3f7               | cmp                 esi, 0x20
            //   66c1f703             | jb                  0x199
            //   d3d7                 | mov                 edx, 0x20
            //   4801e3               | dec                 eax
            //   d2f0                 | lea                 ecx, [ebp + 0x129]
            //   c0f807               | mov                 byte ptr [eax], 0

        $sequence_3 = { f30f7f4de0 660f6f05???????? f30f7f45f0 660f6f0d???????? f30f7f4d00 c74510771a771b c6451477 }
            // n = 7, score = 100
            //   f30f7f4de0           | dec                 eax
            //   660f6f05????????     |                     
            //   f30f7f45f0           | cmp                 ecx, 8
            //   660f6f0d????????     |                     
            //   f30f7f4d00           | jb                  0xdd
            //   c74510771a771b       | dec                 eax
            //   c6451477             | lea                 edx, [ecx*2 + 2]

        $sequence_4 = { 0c40 8845df e8???????? 4c8d05e8180700 488d55c0 488d4da0 e8???????? }
            // n = 7, score = 100
            //   0c40                 | nop                 dword ptr [eax + eax]
            //   8845df               | dec                 ecx
            //   e8????????           |                     
            //   4c8d05e8180700       | mov                 edx, esi
            //   488d55c0             | dec                 eax
            //   488d4da0             | lea                 ecx, [esp + 0x69]
            //   e8????????           |                     

        $sequence_5 = { 33c0 48894310 48c7431807000000 668903 488b4c2458 4833cc e8???????? }
            // n = 7, score = 100
            //   33c0                 | lea                 ecx, [ebp - 0x40]
            //   48894310             | mov                 byte ptr [ebp - 0x34], al
            //   48c7431807000000     | xor                 eax, eax
            //   668903               | mov                 byte ptr [ebp - 0x35], al
            //   488b4c2458           | xor                 edx, edx
            //   4833cc               | dec                 eax
            //   e8????????           |                     

        $sequence_6 = { 33d2 488d4da8 e8???????? 8845b4 b272 488d4da8 e8???????? }
            // n = 7, score = 100
            //   33d2                 | mov                 dl, 0x3c
            //   488d4da8             | mov                 byte ptr [ebp + 0xb11], al
            //   e8????????           |                     
            //   8845b4               | xor                 edx, edx
            //   b272                 | dec                 eax
            //   488d4da8             | lea                 ecx, [ebp + 0x8e0]
            //   e8????????           |                     

        $sequence_7 = { e8???????? 88851e0b0000 b265 488d8de0080000 e8???????? 88851f0b0000 33d2 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   88851e0b0000         | mov                 byte ptr [ebp + 0x1dd], al
            //   b265                 | dec                 eax
            //   488d8de0080000       | lea                 ecx, [ebp + 0x150]
            //   e8????????           |                     
            //   88851f0b0000         | mov                 byte ptr [ebp + 0x2dc], al
            //   33d2                 | mov                 dl, 0x44

        $sequence_8 = { e8???????? c60000 ba0f000000 488d4d99 e8???????? c60000 488d4d99 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   c60000               | dec                 eax
            //   ba0f000000           | xor                 eax, esp
            //   488d4d99             | dec                 eax
            //   e8????????           |                     
            //   c60000               | mov                 dword ptr [ebp + 0x2f0], eax
            //   488d4d99             | dec                 eax

        $sequence_9 = { f6d4 660fbec0 0f98c0 488d7f01 0fb6c0 0f94c4 88f0 }
            // n = 7, score = 100
            //   f6d4                 | dec                 ecx
            //   660fbec0             | mov                 dword ptr [edi], ebx
            //   0f98c0               | dec                 eax
            //   488d7f01             | add                 esp, 0x20
            //   0fb6c0               | inc                 ecx
            //   0f94c4               | pop                 edi
            //   88f0                 | inc                 ecx

    condition:
        7 of them and filesize < 3921930
}