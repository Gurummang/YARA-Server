rule win_adylkuzz_auto {

    meta:
        atk_type = "win.adylkuzz."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.adylkuzz."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adylkuzz"
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
        $sequence_0 = { f5 f8 0fb7bc79b0010000 81fa00000001 0f833a000000 3b45fc 0f83c3fc0100 }
            // n = 7, score = 100
            //   f5                   | cmc                 
            //   f8                   | clc                 
            //   0fb7bc79b0010000     | movzx               edi, word ptr [ecx + edi*2 + 0x1b0]
            //   81fa00000001         | cmp                 edx, 0x1000000
            //   0f833a000000         | jae                 0x40
            //   3b45fc               | cmp                 eax, dword ptr [ebp - 4]
            //   0f83c3fc0100         | jae                 0x1fcc9

        $sequence_1 = { 8b44242c 8b4804 894c2428 8b4a04 894c2430 8b08 8b02 }
            // n = 7, score = 100
            //   8b44242c             | mov                 eax, dword ptr [esp + 0x2c]
            //   8b4804               | mov                 ecx, dword ptr [eax + 4]
            //   894c2428             | mov                 dword ptr [esp + 0x28], ecx
            //   8b4a04               | mov                 ecx, dword ptr [edx + 4]
            //   894c2430             | mov                 dword ptr [esp + 0x30], ecx
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b02                 | mov                 eax, dword ptr [edx]

        $sequence_2 = { e8???????? 807e053d 8944240c 8d4340 754b 89e9 bafe00008d }
            // n = 7, score = 100
            //   e8????????           |                     
            //   807e053d             | cmp                 byte ptr [esi + 5], 0x3d
            //   8944240c             | mov                 dword ptr [esp + 0xc], eax
            //   8d4340               | lea                 eax, [ebx + 0x40]
            //   754b                 | jne                 0x4d
            //   89e9                 | mov                 ecx, ebp
            //   bafe00008d           | mov                 edx, 0x8d0000fe

        $sequence_3 = { 891c24 e8???????? c744240401000000 891c24 e8???????? 85c0 7518 }
            // n = 7, score = 100
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   c744240401000000     | mov                 dword ptr [esp + 4], 1
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   7518                 | jne                 0x1a

        $sequence_4 = { f9 663bc9 33d8 03f8 e9???????? 8b442500 660fbdd5 }
            // n = 7, score = 100
            //   f9                   | stc                 
            //   663bc9               | cmp                 cx, cx
            //   33d8                 | xor                 ebx, eax
            //   03f8                 | add                 edi, eax
            //   e9????????           |                     
            //   8b442500             | mov                 eax, dword ptr [ebp]
            //   660fbdd5             | bsr                 dx, bp

        $sequence_5 = { f8 f5 03f8 e9???????? ff742500 055a2dd112 8dad04000000 }
            // n = 7, score = 100
            //   f8                   | clc                 
            //   f5                   | cmc                 
            //   03f8                 | add                 edi, eax
            //   e9????????           |                     
            //   ff742500             | push                dword ptr [ebp]
            //   055a2dd112           | add                 eax, 0x12d12d5a
            //   8dad04000000         | lea                 ebp, [ebp + 4]

        $sequence_6 = { 89442408 8b4510 89442404 8b03 890424 e8???????? 8b550c }
            // n = 7, score = 100
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   890424               | mov                 dword ptr [esp], eax
            //   e8????????           |                     
            //   8b550c               | mov                 edx, dword ptr [ebp + 0xc]

        $sequence_7 = { f6c3d8 2dc4275e67 2bce 660fc8 66d3c0 fec8 8d440aa4 }
            // n = 7, score = 100
            //   f6c3d8               | test                bl, 0xd8
            //   2dc4275e67           | sub                 eax, 0x675e27c4
            //   2bce                 | sub                 ecx, esi
            //   660fc8               | bswap               ax
            //   66d3c0               | rol                 ax, cl
            //   fec8                 | dec                 al
            //   8d440aa4             | lea                 eax, [edx + ecx - 0x5c]

        $sequence_8 = { e9???????? 8b4c2500 80c4f7 d2d8 648b01 89442500 81ee04000000 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b4c2500             | mov                 ecx, dword ptr [ebp]
            //   80c4f7               | add                 ah, 0xf7
            //   d2d8                 | rcr                 al, cl
            //   648b01               | mov                 eax, dword ptr fs:[ecx]
            //   89442500             | mov                 dword ptr [ebp], eax
            //   81ee04000000         | sub                 esi, 4

        $sequence_9 = { c7442404ffffffff 891c24 e8???????? 8974240c 89442408 c7442404???????? 891c24 }
            // n = 7, score = 100
            //   c7442404ffffffff     | mov                 dword ptr [esp + 4], 0xffffffff
            //   891c24               | mov                 dword ptr [esp], ebx
            //   e8????????           |                     
            //   8974240c             | mov                 dword ptr [esp + 0xc], esi
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   c7442404????????     |                     
            //   891c24               | mov                 dword ptr [esp], ebx

    condition:
        7 of them and filesize < 6438912
}