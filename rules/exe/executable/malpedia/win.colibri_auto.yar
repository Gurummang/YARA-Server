rule win_colibri_auto {

    meta:
        atk_type = "win.colibri."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.colibri."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.colibri"
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
        $sequence_0 = { 8b4dfc 8d4901 e8???????? 56 56 8bd8 }
            // n = 6, score = 100
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   8d4901               | lea                 ecx, [ecx + 1]
            //   e8????????           |                     
            //   56                   | push                esi
            //   56                   | push                esi
            //   8bd8                 | mov                 ebx, eax

        $sequence_1 = { 0f4575f4 59 e8???????? ba1f90113c 8bc8 e8???????? ffd0 }
            // n = 7, score = 100
            //   0f4575f4             | cmovne              esi, dword ptr [ebp - 0xc]
            //   59                   | pop                 ecx
            //   e8????????           |                     
            //   ba1f90113c           | mov                 edx, 0x3c11901f
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   ffd0                 | call                eax

        $sequence_2 = { 83c602 0fb706 8bd0 6685c0 75e2 8933 33c0 }
            // n = 7, score = 100
            //   83c602               | add                 esi, 2
            //   0fb706               | movzx               eax, word ptr [esi]
            //   8bd0                 | mov                 edx, eax
            //   6685c0               | test                ax, ax
            //   75e2                 | jne                 0xffffffe4
            //   8933                 | mov                 dword ptr [ebx], esi
            //   33c0                 | xor                 eax, eax

        $sequence_3 = { 8bf1 8bfa 897df8 85f6 7502 }
            // n = 5, score = 100
            //   8bf1                 | mov                 esi, ecx
            //   8bfa                 | mov                 edi, edx
            //   897df8               | mov                 dword ptr [ebp - 8], edi
            //   85f6                 | test                esi, esi
            //   7502                 | jne                 4

        $sequence_4 = { 897c2440 57 eba2 8364243c00 eb1b }
            // n = 5, score = 100
            //   897c2440             | mov                 dword ptr [esp + 0x40], edi
            //   57                   | push                edi
            //   eba2                 | jmp                 0xffffffa4
            //   8364243c00           | and                 dword ptr [esp + 0x3c], 0
            //   eb1b                 | jmp                 0x1d

        $sequence_5 = { 8d8578f9ffff 33ff 6804010000 50 57 6a02 59 }
            // n = 7, score = 100
            //   8d8578f9ffff         | lea                 eax, [ebp - 0x688]
            //   33ff                 | xor                 edi, edi
            //   6804010000           | push                0x104
            //   50                   | push                eax
            //   57                   | push                edi
            //   6a02                 | push                2
            //   59                   | pop                 ecx

        $sequence_6 = { 8365f800 50 e8???????? 59 85c0 7413 8b4dfc }
            // n = 7, score = 100
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   50                   | push                eax
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   7413                 | je                  0x15
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]

        $sequence_7 = { 668945a4 6689855effffff 66894d96 59 6a76 58 6a69 }
            // n = 7, score = 100
            //   668945a4             | mov                 word ptr [ebp - 0x5c], ax
            //   6689855effffff       | mov                 word ptr [ebp - 0xa2], ax
            //   66894d96             | mov                 word ptr [ebp - 0x6a], cx
            //   59                   | pop                 ecx
            //   6a76                 | push                0x76
            //   58                   | pop                 eax
            //   6a69                 | push                0x69

        $sequence_8 = { 7445 8b4878 85c9 743e 33ff 39787c 7437 }
            // n = 7, score = 100
            //   7445                 | je                  0x47
            //   8b4878               | mov                 ecx, dword ptr [eax + 0x78]
            //   85c9                 | test                ecx, ecx
            //   743e                 | je                  0x40
            //   33ff                 | xor                 edi, edi
            //   39787c               | cmp                 dword ptr [eax + 0x7c], edi
            //   7437                 | je                  0x39

        $sequence_9 = { c1e81f 8d0448 8b0c85c0124000 8d45d4 }
            // n = 4, score = 100
            //   c1e81f               | shr                 eax, 0x1f
            //   8d0448               | lea                 eax, [eax + ecx*2]
            //   8b0c85c0124000       | mov                 ecx, dword ptr [eax*4 + 0x4012c0]
            //   8d45d4               | lea                 eax, [ebp - 0x2c]

    condition:
        7 of them and filesize < 51200
}