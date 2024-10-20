rule win_maze_auto {

    meta:
        atk_type = "win.maze."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.maze."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maze"
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
        $sequence_0 = { 53 57 56 83ec10 8b4510 8b4d0c }
            // n = 6, score = 2400
            //   53                   | push                ebx
            //   57                   | push                edi
            //   56                   | push                esi
            //   83ec10               | sub                 esp, 0x10
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_1 = { 8945f0 c745f000000000 8b45f0 83c410 5e 5f }
            // n = 6, score = 2400
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   8b45f0               | mov                 eax, dword ptr [ebp - 0x10]
            //   83c410               | add                 esp, 0x10
            //   5e                   | pop                 esi
            //   5f                   | pop                 edi

        $sequence_2 = { 60 8b7d08 8b4d10 8b450c f3aa 61 8945f0 }
            // n = 7, score = 2400
            //   60                   | pushal              
            //   8b7d08               | mov                 edi, dword ptr [ebp + 8]
            //   8b4d10               | mov                 ecx, dword ptr [ebp + 0x10]
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   61                   | popal               
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax

        $sequence_3 = { 83ec10 8b4510 8b4d0c 8b5508 837d0800 8945ec }
            // n = 6, score = 2400
            //   83ec10               | sub                 esp, 0x10
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax

        $sequence_4 = { 8945ec 894de8 8955e4 7509 c745f000000000 eb17 60 }
            // n = 7, score = 2400
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   8955e4               | mov                 dword ptr [ebp - 0x1c], edx
            //   7509                 | jne                 0xb
            //   c745f000000000       | mov                 dword ptr [ebp - 0x10], 0
            //   eb17                 | jmp                 0x19
            //   60                   | pushal              

        $sequence_5 = { 89c8 0500000001 83d200 89d7 }
            // n = 4, score = 2300
            //   89c8                 | mov                 eax, ecx
            //   0500000001           | add                 eax, 0x1000000
            //   83d200               | adc                 edx, 0
            //   89d7                 | mov                 edi, edx

        $sequence_6 = { 89c7 e8???????? 83c40c 57 55 8dbc24f4000000 }
            // n = 6, score = 2300
            //   89c7                 | mov                 edi, eax
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   57                   | push                edi
            //   55                   | push                ebp
            //   8dbc24f4000000       | lea                 edi, [esp + 0xf4]

        $sequence_7 = { 89c8 01d6 ba53c6f0ff f7e2 }
            // n = 4, score = 2300
            //   89c8                 | mov                 eax, ecx
            //   01d6                 | add                 esi, edx
            //   ba53c6f0ff           | mov                 edx, 0xfff0c653
            //   f7e2                 | mul                 edx

        $sequence_8 = { 41 41 41 41 41 41 41 }
            // n = 7, score = 1600
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx
            //   41                   | inc                 ecx

        $sequence_9 = { 83ec20 56 be???????? 56 6a00 6801001200 }
            // n = 6, score = 1400
            //   83ec20               | sub                 esp, 0x20
            //   56                   | push                esi
            //   be????????           |                     
            //   56                   | push                esi
            //   6a00                 | push                0
            //   6801001200           | push                0x120001

        $sequence_10 = { 8d45ec 56 8945f8 6a00 8d45f4 50 c745f40c000000 }
            // n = 7, score = 1400
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   56                   | push                esi
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   6a00                 | push                0
            //   8d45f4               | lea                 eax, [ebp - 0xc]
            //   50                   | push                eax
            //   c745f40c000000       | mov                 dword ptr [ebp - 0xc], 0xc

        $sequence_11 = { b904000000 6bd109 8b4d08 8b941100100000 c1ea0a }
            // n = 5, score = 100
            //   b904000000           | mov                 ecx, 4
            //   6bd109               | imul                edx, ecx, 9
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b941100100000       | mov                 edx, dword ptr [ecx + edx + 0x1000]
            //   c1ea0a               | shr                 edx, 0xa

        $sequence_12 = { b948040000 b8cccccccc f3ab a1???????? 33c5 8945ec 50 }
            // n = 7, score = 100
            //   b948040000           | mov                 ecx, 0x448
            //   b8cccccccc           | mov                 eax, 0xcccccccc
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   a1????????           |                     
            //   33c5                 | xor                 eax, ebp
            //   8945ec               | mov                 dword ptr [ebp - 0x14], eax
            //   50                   | push                eax

        $sequence_13 = { 898d6cfeffff 8b4dfc 8b5508 8b848a10080000 }
            // n = 4, score = 100
            //   898d6cfeffff         | mov                 dword ptr [ebp - 0x194], ecx
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b848a10080000       | mov                 eax, dword ptr [edx + ecx*4 + 0x810]

        $sequence_14 = { 8b8c1040100000 c1e10a ba04000000 c1e200 8b4508 8b941040100000 c1ea16 }
            // n = 7, score = 100
            //   8b8c1040100000       | mov                 ecx, dword ptr [eax + edx + 0x1040]
            //   c1e10a               | shl                 ecx, 0xa
            //   ba04000000           | mov                 edx, 4
            //   c1e200               | shl                 edx, 0
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8b941040100000       | mov                 edx, dword ptr [eax + edx + 0x1040]
            //   c1ea16               | shr                 edx, 0x16

        $sequence_15 = { 899594fdffff 8b8d9cfdffff 338d98fdffff 038d94fdffff 8b55fc }
            // n = 5, score = 100
            //   899594fdffff         | mov                 dword ptr [ebp - 0x26c], edx
            //   8b8d9cfdffff         | mov                 ecx, dword ptr [ebp - 0x264]
            //   338d98fdffff         | xor                 ecx, dword ptr [ebp - 0x268]
            //   038d94fdffff         | add                 ecx, dword ptr [ebp - 0x26c]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]

        $sequence_16 = { 8b54813c c1e209 8b45fc 8b4d08 8b44813c }
            // n = 5, score = 100
            //   8b54813c             | mov                 edx, dword ptr [ecx + eax*4 + 0x3c]
            //   c1e209               | shl                 edx, 9
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b44813c             | mov                 eax, dword ptr [ecx + eax*4 + 0x3c]

        $sequence_17 = { 8985e4feffff 8b45fc 8b4d08 8b548134 }
            // n = 4, score = 100
            //   8985e4feffff         | mov                 dword ptr [ebp - 0x11c], eax
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4d08               | mov                 ecx, dword ptr [ebp + 8]
            //   8b548134             | mov                 edx, dword ptr [ecx + eax*4 + 0x34]

        $sequence_18 = { 8b4dfc 8b5508 8b848a1c080000 c1e017 8b4dfc 8b5508 8b8c8a1c080000 }
            // n = 7, score = 100
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b848a1c080000       | mov                 eax, dword ptr [edx + ecx*4 + 0x81c]
            //   c1e017               | shl                 eax, 0x17
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   8b8c8a1c080000       | mov                 ecx, dword ptr [edx + ecx*4 + 0x81c]

    condition:
        7 of them and filesize < 2318336
}