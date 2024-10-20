rule win_stresspaint_auto {

    meta:
        atk_type = "win.stresspaint."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.stresspaint."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stresspaint"
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
        $sequence_0 = { 0103 014510 294514 83665800 }
            // n = 4, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   014510               | add                 dword ptr [ebp + 0x10], eax
            //   294514               | sub                 dword ptr [ebp + 0x14], eax
            //   83665800             | and                 dword ptr [esi + 0x58], 0

        $sequence_1 = { 8d540208 8908 8d4a04 8a5202 51 }
            // n = 5, score = 100
            //   8d540208             | lea                 edx, [edx + eax + 8]
            //   8908                 | mov                 dword ptr [eax], ecx
            //   8d4a04               | lea                 ecx, [edx + 4]
            //   8a5202               | mov                 dl, byte ptr [edx + 2]
            //   51                   | push                ecx

        $sequence_2 = { 8d540203 3bea 7e4d 8b6c241c }
            // n = 4, score = 100
            //   8d540203             | lea                 edx, [edx + eax + 3]
            //   3bea                 | cmp                 ebp, edx
            //   7e4d                 | jle                 0x4f
            //   8b6c241c             | mov                 ebp, dword ptr [esp + 0x1c]

        $sequence_3 = { 0106 83560400 837d1c00 7494 }
            // n = 4, score = 100
            //   0106                 | add                 dword ptr [esi], eax
            //   83560400             | adc                 dword ptr [esi + 4], 0
            //   837d1c00             | cmp                 dword ptr [ebp + 0x1c], 0
            //   7494                 | je                  0xffffff96

        $sequence_4 = { 0103 ebaa 8b442408 56 }
            // n = 4, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   ebaa                 | jmp                 0xffffffac
            //   8b442408             | mov                 eax, dword ptr [esp + 8]
            //   56                   | push                esi

        $sequence_5 = { 0103 014510 294674 8b4674 }
            // n = 4, score = 100
            //   0103                 | add                 dword ptr [ebx], eax
            //   014510               | add                 dword ptr [ebp + 0x10], eax
            //   294674               | sub                 dword ptr [esi + 0x74], eax
            //   8b4674               | mov                 eax, dword ptr [esi + 0x74]

        $sequence_6 = { 0107 115f04 3bcb 7508 }
            // n = 4, score = 100
            //   0107                 | add                 dword ptr [edi], eax
            //   115f04               | adc                 dword ptr [edi + 4], ebx
            //   3bcb                 | cmp                 ecx, ebx
            //   7508                 | jne                 0xa

        $sequence_7 = { 0108 8b8e44010000 114804 8b4f18 }
            // n = 4, score = 100
            //   0108                 | add                 dword ptr [eax], ecx
            //   8b8e44010000         | mov                 ecx, dword ptr [esi + 0x144]
            //   114804               | adc                 dword ptr [eax + 4], ecx
            //   8b4f18               | mov                 ecx, dword ptr [edi + 0x18]

        $sequence_8 = { 0107 83570400 85c9 7508 }
            // n = 4, score = 100
            //   0107                 | add                 dword ptr [edi], eax
            //   83570400             | adc                 dword ptr [edi + 4], 0
            //   85c9                 | test                ecx, ecx
            //   7508                 | jne                 0xa

        $sequence_9 = { 010b 8945fc 8bc2 83530400 }
            // n = 4, score = 100
            //   010b                 | add                 dword ptr [ebx], ecx
            //   8945fc               | mov                 dword ptr [ebp - 4], eax
            //   8bc2                 | mov                 eax, edx
            //   83530400             | adc                 dword ptr [ebx + 4], 0

        $sequence_10 = { 8d5318 c7432400200000 66897312 c6431100 890a }
            // n = 5, score = 100
            //   8d5318               | lea                 edx, [ebx + 0x18]
            //   c7432400200000       | mov                 dword ptr [ebx + 0x24], 0x2000
            //   66897312             | mov                 word ptr [ebx + 0x12], si
            //   c6431100             | mov                 byte ptr [ebx + 0x11], 0
            //   890a                 | mov                 dword ptr [edx], ecx

        $sequence_11 = { 8d540201 52 51 6a39 55 }
            // n = 5, score = 100
            //   8d540201             | lea                 edx, [edx + eax + 1]
            //   52                   | push                edx
            //   51                   | push                ecx
            //   6a39                 | push                0x39
            //   55                   | push                ebp

        $sequence_12 = { 8d540101 8bc5 89542430 8b542450 }
            // n = 4, score = 100
            //   8d540101             | lea                 edx, [ecx + eax + 1]
            //   8bc5                 | mov                 eax, ebp
            //   89542430             | mov                 dword ptr [esp + 0x30], edx
            //   8b542450             | mov                 edx, dword ptr [esp + 0x50]

        $sequence_13 = { 8d5338 3b02 740a 41 83c250 3bcf }
            // n = 6, score = 100
            //   8d5338               | lea                 edx, [ebx + 0x38]
            //   3b02                 | cmp                 eax, dword ptr [edx]
            //   740a                 | je                  0xc
            //   41                   | inc                 ecx
            //   83c250               | add                 edx, 0x50
            //   3bcf                 | cmp                 ecx, edi

        $sequence_14 = { 8d540201 8915???????? 33c0 8bd6 }
            // n = 4, score = 100
            //   8d540201             | lea                 edx, [edx + eax + 1]
            //   8915????????         |                     
            //   33c0                 | xor                 eax, eax
            //   8bd6                 | mov                 edx, esi

        $sequence_15 = { 8d540208 8b4500 c70100000000 8b4c2430 }
            // n = 4, score = 100
            //   8d540208             | lea                 edx, [edx + eax + 8]
            //   8b4500               | mov                 eax, dword ptr [ebp]
            //   c70100000000         | mov                 dword ptr [ecx], 0
            //   8b4c2430             | mov                 ecx, dword ptr [esp + 0x30]

    condition:
        7 of them and filesize < 1155072
}