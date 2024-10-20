rule win_paladin_auto {

    meta:
        atk_type = "win.paladin."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.paladin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.paladin"
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
        $sequence_0 = { c20800 8d5d04 50 52 }
            // n = 4, score = 200
            //   c20800               | ret                 8
            //   8d5d04               | lea                 ebx, [ebp + 4]
            //   50                   | push                eax
            //   52                   | push                edx

        $sequence_1 = { ffd7 8b4614 6aff 50 ffd7 8b4e10 }
            // n = 6, score = 200
            //   ffd7                 | call                edi
            //   8b4614               | mov                 eax, dword ptr [esi + 0x14]
            //   6aff                 | push                -1
            //   50                   | push                eax
            //   ffd7                 | call                edi
            //   8b4e10               | mov                 ecx, dword ptr [esi + 0x10]

        $sequence_2 = { 0faff0 83c61f c70728000000 c1fe03 83e6fc 894704 0faff1 }
            // n = 7, score = 200
            //   0faff0               | imul                esi, eax
            //   83c61f               | add                 esi, 0x1f
            //   c70728000000         | mov                 dword ptr [edi], 0x28
            //   c1fe03               | sar                 esi, 3
            //   83e6fc               | and                 esi, 0xfffffffc
            //   894704               | mov                 dword ptr [edi + 4], eax
            //   0faff1               | imul                esi, ecx

        $sequence_3 = { 53 55 56 8bf1 57 b918000000 33c0 }
            // n = 7, score = 200
            //   53                   | push                ebx
            //   55                   | push                ebp
            //   56                   | push                esi
            //   8bf1                 | mov                 esi, ecx
            //   57                   | push                edi
            //   b918000000           | mov                 ecx, 0x18
            //   33c0                 | xor                 eax, eax

        $sequence_4 = { 33c0 8a41ff 8d1440 8d1492 8d1492 8d1cd0 33d2 }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   8a41ff               | mov                 al, byte ptr [ecx - 1]
            //   8d1440               | lea                 edx, [eax + eax*2]
            //   8d1492               | lea                 edx, [edx + edx*4]
            //   8d1492               | lea                 edx, [edx + edx*4]
            //   8d1cd0               | lea                 ebx, [eax + edx*8]
            //   33d2                 | xor                 edx, edx

        $sequence_5 = { 687f030000 6a00 68???????? 8bf0 }
            // n = 4, score = 200
            //   687f030000           | push                0x37f
            //   6a00                 | push                0
            //   68????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_6 = { 33c0 8dbc24a0000000 33d2 899c249c000000 83c40c 89942484000000 f3ab }
            // n = 7, score = 200
            //   33c0                 | xor                 eax, eax
            //   8dbc24a0000000       | lea                 edi, [esp + 0xa0]
            //   33d2                 | xor                 edx, edx
            //   899c249c000000       | mov                 dword ptr [esp + 0x9c], ebx
            //   83c40c               | add                 esp, 0xc
            //   89942484000000       | mov                 dword ptr [esp + 0x84], edx
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax

        $sequence_7 = { 81c468020000 c20400 53 c645002e bb01000000 eb04 8b742414 }
            // n = 7, score = 200
            //   81c468020000         | add                 esp, 0x268
            //   c20400               | ret                 4
            //   53                   | push                ebx
            //   c645002e             | mov                 byte ptr [ebp], 0x2e
            //   bb01000000           | mov                 ebx, 1
            //   eb04                 | jmp                 6
            //   8b742414             | mov                 esi, dword ptr [esp + 0x14]

        $sequence_8 = { 8b4518 83f804 7427 83f802 7422 83f806 741d }
            // n = 7, score = 200
            //   8b4518               | mov                 eax, dword ptr [ebp + 0x18]
            //   83f804               | cmp                 eax, 4
            //   7427                 | je                  0x29
            //   83f802               | cmp                 eax, 2
            //   7422                 | je                  0x24
            //   83f806               | cmp                 eax, 6
            //   741d                 | je                  0x1f

        $sequence_9 = { 83f80d 0f8661010000 eb04 8b6c2410 }
            // n = 4, score = 200
            //   83f80d               | cmp                 eax, 0xd
            //   0f8661010000         | jbe                 0x167
            //   eb04                 | jmp                 6
            //   8b6c2410             | mov                 ebp, dword ptr [esp + 0x10]

    condition:
        7 of them and filesize < 106496
}