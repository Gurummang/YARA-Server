rule win_blackcat_auto {

    meta:
        atk_type = "win.blackcat."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.blackcat."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackcat"
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
        $sequence_0 = { c3 894608 c7460400000000 b001 ebe8 89c2 }
            // n = 6, score = 600
            //   c3                   | ret                 
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   c7460400000000       | mov                 dword ptr [esi + 4], 0
            //   b001                 | mov                 al, 1
            //   ebe8                 | jmp                 0xffffffea
            //   89c2                 | mov                 edx, eax

        $sequence_1 = { 7260 8b06 01d8 51 57 50 89cf }
            // n = 7, score = 600
            //   7260                 | jb                  0x62
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   01d8                 | add                 eax, ebx
            //   51                   | push                ecx
            //   57                   | push                edi
            //   50                   | push                eax
            //   89cf                 | mov                 edi, ecx

        $sequence_2 = { 8975dc 8955e0 eb07 31c0 b902000000 }
            // n = 5, score = 600
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   8955e0               | mov                 dword ptr [ebp - 0x20], edx
            //   eb07                 | jmp                 9
            //   31c0                 | xor                 eax, eax
            //   b902000000           | mov                 ecx, 2

        $sequence_3 = { b104 eb0f e8???????? 89c2 c1e018 31c9 }
            // n = 6, score = 600
            //   b104                 | mov                 cl, 4
            //   eb0f                 | jmp                 0x11
            //   e8????????           |                     
            //   89c2                 | mov                 edx, eax
            //   c1e018               | shl                 eax, 0x18
            //   31c9                 | xor                 ecx, ecx

        $sequence_4 = { 7504 3c02 7351 88c4 8975cc }
            // n = 5, score = 600
            //   7504                 | jne                 6
            //   3c02                 | cmp                 al, 2
            //   7351                 | jae                 0x53
            //   88c4                 | mov                 ah, al
            //   8975cc               | mov                 dword ptr [ebp - 0x34], esi

        $sequence_5 = { 81f9cf040000 0f8fe4000000 81f96b040000 0f84b4010000 81f976040000 }
            // n = 5, score = 600
            //   81f9cf040000         | cmp                 ecx, 0x4cf
            //   0f8fe4000000         | jg                  0xea
            //   81f96b040000         | cmp                 ecx, 0x46b
            //   0f84b4010000         | je                  0x1ba
            //   81f976040000         | cmp                 ecx, 0x476

        $sequence_6 = { 83ec08 a1???????? c745f800000000 c745fc00000000 85c0 7408 8d4df8 }
            // n = 7, score = 600
            //   83ec08               | sub                 esp, 8
            //   a1????????           |                     
            //   c745f800000000       | mov                 dword ptr [ebp - 8], 0
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   85c0                 | test                eax, eax
            //   7408                 | je                  0xa
            //   8d4df8               | lea                 ecx, [ebp - 8]

        $sequence_7 = { 8d45f8 50 e8???????? 8b45f8 8b55fc 83c408 }
            // n = 6, score = 600
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   8b55fc               | mov                 edx, dword ptr [ebp - 4]
            //   83c408               | add                 esp, 8

        $sequence_8 = { 895804 897008 eb0b 8b45e8 894708 }
            // n = 5, score = 600
            //   895804               | mov                 dword ptr [eax + 4], ebx
            //   897008               | mov                 dword ptr [eax + 8], esi
            //   eb0b                 | jmp                 0xd
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   894708               | mov                 dword ptr [edi + 8], eax

        $sequence_9 = { ff45e4 8a02 42 8955e8 }
            // n = 4, score = 600
            //   ff45e4               | inc                 dword ptr [ebp - 0x1c]
            //   8a02                 | mov                 al, byte ptr [edx]
            //   42                   | inc                 edx
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx

    condition:
        7 of them and filesize < 29981696
}