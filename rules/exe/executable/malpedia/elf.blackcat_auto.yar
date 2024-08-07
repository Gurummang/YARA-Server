rule elf_blackcat_auto {

    meta:
        atk_type = "elf.blackcat."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects elf.blackcat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.blackcat"
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
        $sequence_0 = { e8???????? 0f0b 90 90 90 90 53 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   0f0b                 | mov                 eax, ebx
            //   90                   | mov                 eax, ebx
            //   90                   | jae                 0x15e6
            //   90                   | shr                 eax, 6
            //   90                   | mov                 edx, ebx
            //   53                   | and                 edx, 0x3f

        $sequence_1 = { 69c0???????? c1e811 6bf064 29f2 0fb7d2 }
            // n = 5, score = 200
            //   69c0????????         |                     
            //   c1e811               | mov                 dword ptr [esp + 0x58], 8
            //   6bf064               | dec                 eax
            //   29f2                 | lea                 edi, [0x121f94]
            //   0fb7d2               | dec                 eax

        $sequence_2 = { e8???????? 0f0b 90 53 }
            // n = 4, score = 200
            //   e8????????           |                     
            //   0f0b                 | mov                 edi, dword ptr [ecx + 0x14]
            //   90                   | mov                 ebp, dword ptr [ecx + 0x18]
            //   53                   | mov                 ebx, dword ptr [ecx + 0xc]

        $sequence_3 = { 89c1 3d???????? 7319 c1e906 }
            // n = 4, score = 200
            //   89c1                 | mov                 ebp, dword ptr [esp + 0x84]
            //   3d????????           |                     
            //   7319                 | mov                 dword ptr [esi + 8], 0xffffffff
            //   c1e906               | cmp                 dword ptr [esi + 8], 0

        $sequence_4 = { 660f7f8424f0010000 660f7f8424e0010000 660f7f8424d0010000 660f7f8424c0010000 660f7f8424b0010000 }
            // n = 5, score = 200
            //   660f7f8424f0010000     | dec    eax
            //   660f7f8424e0010000     | cmp    eax, -1
            //   660f7f8424d0010000     | jne    0x22c
            //   660f7f8424c0010000     | dec    eax
            //   660f7f8424b0010000     | lea    esi, [esp + 0x20]

        $sequence_5 = { d1e9 01d1 c1e902 8d14cd00000000 }
            // n = 4, score = 200
            //   d1e9                 | mov                 esi, dword ptr [esp + 0x14]
            //   01d1                 | mov                 eax, edi
            //   c1e902               | lea                 edi, [ecx + edx]
            //   8d14cd00000000       | lea                 esi, [esi - 0x4b514]

        $sequence_6 = { b801000000 81f9???????? 0f823fffffff b802000000 }
            // n = 4, score = 200
            //   b801000000           | mov                 ecx, dword ptr [esp + 0x10]
            //   81f9????????         |                     
            //   0f823fffffff         | movsd               qword ptr [eax], xmm0
            //   b802000000           | mov                 dword ptr [eax + 8], edi

        $sequence_7 = { 69c0???????? c1e810 29c2 0fb7d2 d1ea }
            // n = 5, score = 200
            //   69c0????????         |                     
            //   c1e810               | dec                 eax
            //   29c2                 | mov                 esi, dword ptr [esp + 0x20]
            //   0fb7d2               | dec                 eax
            //   d1ea                 | mov                 dword ptr [esp + 0x58], 3

        $sequence_8 = { 762a 0fb6c8 8d1489 8d0cd1 }
            // n = 4, score = 200
            //   762a                 | mov                 ebx, dword ptr [esp + 0x138]
            //   0fb6c8               | dec                 eax
            //   8d1489               | mov                 eax, dword ptr [esp + 0xe0]
            //   8d0cd1               | mov                 cl, 1

        $sequence_9 = { e8???????? 0f0b e8???????? 0f0b 90 90 90 }
            // n = 7, score = 200
            //   e8????????           |                     
            //   0f0b                 | dec                 ecx
            //   e8????????           |                     
            //   0f0b                 | mov                 dword ptr [ecx], eax
            //   90                   | dec                 ecx
            //   90                   | mov                 dword ptr [ecx + 8], ebx
            //   90                   | dec                 ecx

    condition:
        7 of them and filesize < 8011776
}