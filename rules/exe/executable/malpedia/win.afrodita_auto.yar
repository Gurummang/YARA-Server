rule win_afrodita_auto {

    meta:
        atk_type = "win.afrodita."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.afrodita."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.afrodita"
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
        $sequence_0 = { 83e615 83ce02 89710c 23c6 74a5 a804 740a }
            // n = 7, score = 300
            //   83e615               | and                 esi, 0x15
            //   83ce02               | or                  esi, 2
            //   89710c               | mov                 dword ptr [ecx + 0xc], esi
            //   23c6                 | and                 eax, esi
            //   74a5                 | je                  0xffffffa7
            //   a804                 | test                al, 4
            //   740a                 | je                  0xc

        $sequence_1 = { e8???????? 56 8d8558ffffff c745fc05000000 57 83cb08 50 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   56                   | push                esi
            //   8d8558ffffff         | lea                 eax, [ebp - 0xa8]
            //   c745fc05000000       | mov                 dword ptr [ebp - 4], 5
            //   57                   | push                edi
            //   83cb08               | or                  ebx, 8
            //   50                   | push                eax

        $sequence_2 = { e8???????? eb02 33ff 8bb57cffffff c745fcffffffff 8b4e2c 85c9 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   eb02                 | jmp                 4
            //   33ff                 | xor                 edi, edi
            //   8bb57cffffff         | mov                 esi, dword ptr [ebp - 0x84]
            //   c745fcffffffff       | mov                 dword ptr [ebp - 4], 0xffffffff
            //   8b4e2c               | mov                 ecx, dword ptr [esi + 0x2c]
            //   85c9                 | test                ecx, ecx

        $sequence_3 = { 8d4f10 e8???????? 8b0f 8b4904 03cf 85c0 7454 }
            // n = 7, score = 300
            //   8d4f10               | lea                 ecx, [edi + 0x10]
            //   e8????????           |                     
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8b4904               | mov                 ecx, dword ptr [ecx + 4]
            //   03cf                 | add                 ecx, edi
            //   85c0                 | test                eax, eax
            //   7454                 | je                  0x56

        $sequence_4 = { 0f1040c0 0f1149a0 0f104c30c0 8b75e8 660fefc8 0f1040d0 0f114c30c0 }
            // n = 7, score = 300
            //   0f1040c0             | movups              xmm0, xmmword ptr [eax - 0x40]
            //   0f1149a0             | movups              xmmword ptr [ecx - 0x60], xmm1
            //   0f104c30c0           | movups              xmm1, xmmword ptr [eax + esi - 0x40]
            //   8b75e8               | mov                 esi, dword ptr [ebp - 0x18]
            //   660fefc8             | pxor                xmm1, xmm0
            //   0f1040d0             | movups              xmm0, xmmword ptr [eax - 0x30]
            //   0f114c30c0           | movups              xmmword ptr [eax + esi - 0x40], xmm1

        $sequence_5 = { 897304 c6430801 53 8d4de4 }
            // n = 4, score = 300
            //   897304               | mov                 dword ptr [ebx + 4], esi
            //   c6430801             | mov                 byte ptr [ebx + 8], 1
            //   53                   | push                ebx
            //   8d4de4               | lea                 ecx, [ebp - 0x1c]

        $sequence_6 = { 8b4b08 8b7b0c 897df8 894dfc 3bce }
            // n = 5, score = 300
            //   8b4b08               | mov                 ecx, dword ptr [ebx + 8]
            //   8b7b0c               | mov                 edi, dword ptr [ebx + 0xc]
            //   897df8               | mov                 dword ptr [ebp - 8], edi
            //   894dfc               | mov                 dword ptr [ebp - 4], ecx
            //   3bce                 | cmp                 ecx, esi

        $sequence_7 = { e8???????? 83c40c c744be0400000000 c704be00000000 5e 5b }
            // n = 6, score = 300
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c744be0400000000     | mov                 dword ptr [esi + edi*4 + 4], 0
            //   c704be00000000       | mov                 dword ptr [esi + edi*4], 0
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_8 = { 50 8bcb ff5720 0375d4 8bce e8???????? }
            // n = 6, score = 300
            //   50                   | push                eax
            //   8bcb                 | mov                 ecx, ebx
            //   ff5720               | call                dword ptr [edi + 0x20]
            //   0375d4               | add                 esi, dword ptr [ebp - 0x2c]
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_9 = { 894f04 8bc7 e9???????? 83f854 0f8fdc010000 83f853 0f8dea020000 }
            // n = 7, score = 300
            //   894f04               | mov                 dword ptr [edi + 4], ecx
            //   8bc7                 | mov                 eax, edi
            //   e9????????           |                     
            //   83f854               | cmp                 eax, 0x54
            //   0f8fdc010000         | jg                  0x1e2
            //   83f853               | cmp                 eax, 0x53
            //   0f8dea020000         | jge                 0x2f0

    condition:
        7 of them and filesize < 2334720
}