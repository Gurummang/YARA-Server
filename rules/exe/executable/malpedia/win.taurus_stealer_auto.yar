rule win_taurus_stealer_auto {

    meta:
        atk_type = "win.taurus_stealer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.taurus_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taurus_stealer"
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
        $sequence_0 = { 56 8b7508 eb12 8d4e1c e8???????? 8bce e8???????? }
            // n = 7, score = 200
            //   56                   | push                esi
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   eb12                 | jmp                 0x14
            //   8d4e1c               | lea                 ecx, [esi + 0x1c]
            //   e8????????           |                     
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_1 = { 8d4de8 e8???????? 85f6 7408 8d4dd0 e8???????? 8b4508 }
            // n = 7, score = 200
            //   8d4de8               | lea                 ecx, [ebp - 0x18]
            //   e8????????           |                     
            //   85f6                 | test                esi, esi
            //   7408                 | je                  0xa
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   e8????????           |                     
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_2 = { 88550f 88450e 8d450e 51 50 8d4d8c e8???????? }
            // n = 7, score = 200
            //   88550f               | mov                 byte ptr [ebp + 0xf], dl
            //   88450e               | mov                 byte ptr [ebp + 0xe], al
            //   8d450e               | lea                 eax, [ebp + 0xe]
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8d4d8c               | lea                 ecx, [ebp - 0x74]
            //   e8????????           |                     

        $sequence_3 = { 51 50 8bce e8???????? 8d4dcc e8???????? 8d4db4 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   50                   | push                eax
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   8d4dcc               | lea                 ecx, [ebp - 0x34]
            //   e8????????           |                     
            //   8d4db4               | lea                 ecx, [ebp - 0x4c]

        $sequence_4 = { 7305 8a5df3 ebf1 8d45f4 c645ff00 50 8bd6 }
            // n = 7, score = 200
            //   7305                 | jae                 7
            //   8a5df3               | mov                 bl, byte ptr [ebp - 0xd]
            //   ebf1                 | jmp                 0xfffffff3
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   c645ff00             | mov                 byte ptr [ebp - 1], 0
            //   50                   | push                eax
            //   8bd6                 | mov                 edx, esi

        $sequence_5 = { 8bc2 c1e802 c1e103 8b0483 d3e8 880432 42 }
            // n = 7, score = 200
            //   8bc2                 | mov                 eax, edx
            //   c1e802               | shr                 eax, 2
            //   c1e103               | shl                 ecx, 3
            //   8b0483               | mov                 eax, dword ptr [ebx + eax*4]
            //   d3e8                 | shr                 eax, cl
            //   880432               | mov                 byte ptr [edx + esi], al
            //   42                   | inc                 edx

        $sequence_6 = { 8d4ddc e8???????? 8d4d90 e8???????? 8d4d84 e8???????? }
            // n = 6, score = 200
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]
            //   e8????????           |                     
            //   8d4d90               | lea                 ecx, [ebp - 0x70]
            //   e8????????           |                     
            //   8d4d84               | lea                 ecx, [ebp - 0x7c]
            //   e8????????           |                     

        $sequence_7 = { c74610fe33b90f c7461465dc040b c74618e3804800 c7461cb5492c0d c7462045909c0f c74624dd90c504 c7462870e8f00e }
            // n = 7, score = 200
            //   c74610fe33b90f       | mov                 dword ptr [esi + 0x10], 0xfb933fe
            //   c7461465dc040b       | mov                 dword ptr [esi + 0x14], 0xb04dc65
            //   c74618e3804800       | mov                 dword ptr [esi + 0x18], 0x4880e3
            //   c7461cb5492c0d       | mov                 dword ptr [esi + 0x1c], 0xd2c49b5
            //   c7462045909c0f       | mov                 dword ptr [esi + 0x20], 0xf9c9045
            //   c74624dd90c504       | mov                 dword ptr [esi + 0x24], 0x4c590dd
            //   c7462870e8f00e       | mov                 dword ptr [esi + 0x28], 0xef0e870

        $sequence_8 = { 0f1145c1 885ddf 0fbe4581 250f000080 7905 48 83c8f0 }
            // n = 7, score = 200
            //   0f1145c1             | movups              xmmword ptr [ebp - 0x3f], xmm0
            //   885ddf               | mov                 byte ptr [ebp - 0x21], bl
            //   0fbe4581             | movsx               eax, byte ptr [ebp - 0x7f]
            //   250f000080           | and                 eax, 0x8000000f
            //   7905                 | jns                 7
            //   48                   | dec                 eax
            //   83c8f0               | or                  eax, 0xfffffff0

        $sequence_9 = { 40 83f806 7305 8a5df2 ebf1 8d45f3 c645f900 }
            // n = 7, score = 200
            //   40                   | inc                 eax
            //   83f806               | cmp                 eax, 6
            //   7305                 | jae                 7
            //   8a5df2               | mov                 bl, byte ptr [ebp - 0xe]
            //   ebf1                 | jmp                 0xfffffff3
            //   8d45f3               | lea                 eax, [ebp - 0xd]
            //   c645f900             | mov                 byte ptr [ebp - 7], 0

    condition:
        7 of them and filesize < 524288
}