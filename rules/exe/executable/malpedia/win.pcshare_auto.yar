rule win_pcshare_auto {

    meta:
        atk_type = "win.pcshare."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.pcshare."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pcshare"
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
        $sequence_0 = { 8b48fc 03f7 8b78f8 8bd1 03fb c1e902 }
            // n = 6, score = 100
            //   8b48fc               | mov                 ecx, dword ptr [eax - 4]
            //   03f7                 | add                 esi, edi
            //   8b78f8               | mov                 edi, dword ptr [eax - 8]
            //   8bd1                 | mov                 edx, ecx
            //   03fb                 | add                 edi, ebx
            //   c1e902               | shr                 ecx, 2

        $sequence_1 = { 33ed 8d0c18 8bc3 99 }
            // n = 4, score = 100
            //   33ed                 | xor                 ebp, ebp
            //   8d0c18               | lea                 ecx, [eax + ebx]
            //   8bc3                 | mov                 eax, ebx
            //   99                   | cdq                 

        $sequence_2 = { e8???????? 85c0 59 743e 8305????????20 8d0c9da0720610 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   59                   | pop                 ecx
            //   743e                 | je                  0x40
            //   8305????????20       |                     
            //   8d0c9da0720610       | lea                 ecx, [ebx*4 + 0x100672a0]

        $sequence_3 = { 8bc6 8b0c8da0720610 8d04c0 80648104fd 8d448104 8bc7 5f }
            // n = 7, score = 100
            //   8bc6                 | mov                 eax, esi
            //   8b0c8da0720610       | mov                 ecx, dword ptr [ecx*4 + 0x100672a0]
            //   8d04c0               | lea                 eax, [eax + eax*8]
            //   80648104fd           | and                 byte ptr [ecx + eax*4 + 4], 0xfd
            //   8d448104             | lea                 eax, [ecx + eax*4 + 4]
            //   8bc7                 | mov                 eax, edi
            //   5f                   | pop                 edi

        $sequence_4 = { 8d4c2418 50 51 e8???????? 83c40c 84c0 7439 }
            // n = 7, score = 100
            //   8d4c2418             | lea                 ecx, [esp + 0x18]
            //   50                   | push                eax
            //   51                   | push                ecx
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   84c0                 | test                al, al
            //   7439                 | je                  0x3b

        $sequence_5 = { c1e705 f6441f0e01 7428 8b4c2474 81e2ffff2f00 895008 8b542440 }
            // n = 7, score = 100
            //   c1e705               | shl                 edi, 5
            //   f6441f0e01           | test                byte ptr [edi + ebx + 0xe], 1
            //   7428                 | je                  0x2a
            //   8b4c2474             | mov                 ecx, dword ptr [esp + 0x74]
            //   81e2ffff2f00         | and                 edx, 0x2fffff
            //   895008               | mov                 dword ptr [eax + 8], edx
            //   8b542440             | mov                 edx, dword ptr [esp + 0x40]

        $sequence_6 = { 51 eb07 8b16 8d441a02 }
            // n = 4, score = 100
            //   51                   | push                ecx
            //   eb07                 | jmp                 9
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   8d441a02             | lea                 eax, [edx + ebx + 2]

        $sequence_7 = { 85c0 7505 b8???????? 8078fffe 732f }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   7505                 | jne                 7
            //   b8????????           |                     
            //   8078fffe             | cmp                 byte ptr [eax - 1], 0xfe
            //   732f                 | jae                 0x31

        $sequence_8 = { 83c418 894c2424 b940000000 f3ab 66ab aa b940000000 }
            // n = 7, score = 100
            //   83c418               | add                 esp, 0x18
            //   894c2424             | mov                 dword ptr [esp + 0x24], ecx
            //   b940000000           | mov                 ecx, 0x40
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   aa                   | stosb               byte ptr es:[edi], al
            //   b940000000           | mov                 ecx, 0x40

        $sequence_9 = { 3bd0 0f8c93fdffff 33ed 5b 8b74243c 8a4c241c }
            // n = 6, score = 100
            //   3bd0                 | cmp                 edx, eax
            //   0f8c93fdffff         | jl                  0xfffffd99
            //   33ed                 | xor                 ebp, ebp
            //   5b                   | pop                 ebx
            //   8b74243c             | mov                 esi, dword ptr [esp + 0x3c]
            //   8a4c241c             | mov                 cl, byte ptr [esp + 0x1c]

    condition:
        7 of them and filesize < 893708
}