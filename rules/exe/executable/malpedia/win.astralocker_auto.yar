rule win_astralocker_auto {

    meta:
        atk_type = "win.astralocker."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.astralocker."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.astralocker"
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
        $sequence_0 = { 8b5508 8b440a04 50 8b0c0a 51 e8???????? }
            // n = 6, score = 500
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b440a04             | mov                 eax, dword ptr [edx + ecx + 4]
            //   50                   | push                eax
            //   8b0c0a               | mov                 ecx, dword ptr [edx + ecx]
            //   51                   | push                ecx
            //   e8????????           |                     

        $sequence_1 = { 83c102 894dfc 837dfc0a 0f83dc000000 8b55fc 8b4508 }
            // n = 6, score = 500
            //   83c102               | add                 ecx, 2
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   837dfc0a             | cmp                 dword ptr [ebp - 4], 0xa
            //   0f83dc000000         | jae                 0xe2
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_2 = { 6bc20a 8b4d08 33d2 33f6 891401 }
            // n = 5, score = 500
            //   6bc20a               | imul                eax, edx, 0xa
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33d2                 | xor                 edx, edx
            //   33f6                 | xor                 esi, esi
            //   891401               | mov                 dword ptr [ecx + eax], edx

        $sequence_3 = { 6bc20a 8b4d08 33d2 33f6 }
            // n = 4, score = 500
            //   6bc20a               | imul                eax, edx, 0xa
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33d2                 | xor                 edx, edx
            //   33f6                 | xor                 esi, esi

        $sequence_4 = { 8b440a04 50 8b0c0a 51 e8???????? 83c408 8945ec }
            // n = 7, score = 500
            //   8b440a04             | mov                 eax, dword ptr [edx + ecx + 4]
            //   50                   | push                eax
            //   8b0c0a               | mov                 ecx, dword ptr [edx + ecx]
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_5 = { 894dfc 837dfc0a 0f83dc000000 8b55fc 8b4508 8b4cd004 }
            // n = 6, score = 500
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   837dfc0a             | cmp                 dword ptr [ebp - 4], 0xa
            //   0f83dc000000         | jae                 0xe2
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4cd004             | mov                 ecx, dword ptr [eax + edx*8 + 4]

        $sequence_6 = { 8b4508 8b4cd004 51 8b14d0 52 e8???????? }
            // n = 6, score = 500
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b4cd004             | mov                 ecx, dword ptr [eax + edx*8 + 4]
            //   51                   | push                ecx
            //   8b14d0               | mov                 edx, dword ptr [eax + edx*8]
            //   52                   | push                edx
            //   e8????????           |                     

        $sequence_7 = { 33c0 33f6 89040a 89740a04 }
            // n = 4, score = 500
            //   33c0                 | xor                 eax, eax
            //   33f6                 | xor                 esi, esi
            //   89040a               | mov                 dword ptr [edx + ecx], eax
            //   89740a04             | mov                 dword ptr [edx + ecx + 4], esi

        $sequence_8 = { ba08000000 6bc20a 8b4d08 33d2 33f6 891401 89740104 }
            // n = 7, score = 500
            //   ba08000000           | mov                 edx, 8
            //   6bc20a               | imul                eax, edx, 0xa
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   33d2                 | xor                 edx, edx
            //   33f6                 | xor                 esi, esi
            //   891401               | mov                 dword ptr [ecx + eax], edx
            //   89740104             | mov                 dword ptr [ecx + eax + 4], esi

        $sequence_9 = { 33c0 33f6 89040a 89740a04 c745fc00000000 eb09 }
            // n = 6, score = 500
            //   33c0                 | xor                 eax, eax
            //   33f6                 | xor                 esi, esi
            //   89040a               | mov                 dword ptr [edx + ecx], eax
            //   89740a04             | mov                 dword ptr [edx + ecx + 4], esi
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   eb09                 | jmp                 0xb

    condition:
        7 of them and filesize < 191488
}