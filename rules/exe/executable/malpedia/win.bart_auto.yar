rule win_bart_auto {

    meta:
        atk_type = "win.bart."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.bart."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bart"
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
        $sequence_0 = { 8b0483 3bd0 772e 7205 80c1ff 79e8 33c9 }
            // n = 7, score = 100
            //   8b0483               | mov                 eax, dword ptr [ebx + eax*4]
            //   3bd0                 | cmp                 edx, eax
            //   772e                 | ja                  0x30
            //   7205                 | jb                  7
            //   80c1ff               | add                 cl, 0xff
            //   79e8                 | jns                 0xffffffea
            //   33c9                 | xor                 ecx, ecx

        $sequence_1 = { 8b0433 03c2 03c1 3bc2 7404 1bc9 }
            // n = 6, score = 100
            //   8b0433               | mov                 eax, dword ptr [ebx + esi]
            //   03c2                 | add                 eax, edx
            //   03c1                 | add                 eax, ecx
            //   3bc2                 | cmp                 eax, edx
            //   7404                 | je                  6
            //   1bc9                 | sbb                 ecx, ecx

        $sequence_2 = { 8a18 894dd0 8955c8 8945cc 57 85f6 }
            // n = 6, score = 100
            //   8a18                 | mov                 bl, byte ptr [eax]
            //   894dd0               | mov                 dword ptr [ebp - 0x30], ecx
            //   8955c8               | mov                 dword ptr [ebp - 0x38], edx
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   57                   | push                edi
            //   85f6                 | test                esi, esi

        $sequence_3 = { 660fd6459c e8???????? 83c410 8d8570ffffff 33c9 ba07000000 }
            // n = 6, score = 100
            //   660fd6459c           | movq                qword ptr [ebp - 0x64], xmm0
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d8570ffffff         | lea                 eax, [ebp - 0x90]
            //   33c9                 | xor                 ecx, ecx
            //   ba07000000           | mov                 edx, 7

        $sequence_4 = { e8???????? 8b7598 8d4d9c 8b5590 0fb606 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   8b7598               | mov                 esi, dword ptr [ebp - 0x68]
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   8b5590               | mov                 edx, dword ptr [ebp - 0x70]
            //   0fb606               | movzx               eax, byte ptr [esi]

        $sequence_5 = { 8b4485dc d3e8 88043a 0fbed3 3bd6 7cde 8bbd58ffffff }
            // n = 7, score = 100
            //   8b4485dc             | mov                 eax, dword ptr [ebp + eax*4 - 0x24]
            //   d3e8                 | shr                 eax, cl
            //   88043a               | mov                 byte ptr [edx + edi], al
            //   0fbed3               | movsx               edx, bl
            //   3bd6                 | cmp                 edx, esi
            //   7cde                 | jl                  0xffffffe0
            //   8bbd58ffffff         | mov                 edi, dword ptr [ebp - 0xa8]

        $sequence_6 = { 7868 8bc8 0fbec2 8b5508 894c2418 8d1482 8a44240e }
            // n = 7, score = 100
            //   7868                 | js                  0x6a
            //   8bc8                 | mov                 ecx, eax
            //   0fbec2               | movsx               eax, dl
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   894c2418             | mov                 dword ptr [esp + 0x18], ecx
            //   8d1482               | lea                 edx, [edx + eax*4]
            //   8a44240e             | mov                 al, byte ptr [esp + 0xe]

        $sequence_7 = { 84db 0f8ed3020000 0fb6d3 8bc7 899564ffffff 0b08 8d4004 }
            // n = 7, score = 100
            //   84db                 | test                bl, bl
            //   0f8ed3020000         | jle                 0x2d9
            //   0fb6d3               | movzx               edx, bl
            //   8bc7                 | mov                 eax, edi
            //   899564ffffff         | mov                 dword ptr [ebp - 0x9c], edx
            //   0b08                 | or                  ecx, dword ptr [eax]
            //   8d4004               | lea                 eax, [eax + 4]

        $sequence_8 = { 8bca e8???????? 8b4dfc 83c438 33cd 5f 5e }
            // n = 7, score = 100
            //   8bca                 | mov                 ecx, edx
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c438               | add                 esp, 0x38
            //   33cd                 | xor                 ecx, ebp
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi

        $sequence_9 = { 0f88ff000000 8b7df4 83c706 42 }
            // n = 4, score = 100
            //   0f88ff000000         | js                  0x105
            //   8b7df4               | mov                 edi, dword ptr [ebp - 0xc]
            //   83c706               | add                 edi, 6
            //   42                   | inc                 edx

    condition:
        7 of them and filesize < 163840
}