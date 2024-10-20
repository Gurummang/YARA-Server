rule win_noxplayer_auto {

    meta:
        atk_type = "win.noxplayer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.noxplayer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.noxplayer"
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
        $sequence_0 = { 488941b0 488b42b8 41b8a8000000 488941b8 488b42c0 488941c0 8b42c8 }
            // n = 7, score = 100
            //   488941b0             | cmp                 byte ptr [ebx + 0x29], 0
            //   488b42b8             | dec                 esp
            //   41b8a8000000         | mov                 eax, ebx
            //   488941b8             | jne                 0x1f3
            //   488b42c0             | dec                 eax
            //   488941c0             | mov                 eax, dword ptr [ebx + 0x10]
            //   8b42c8               | cmp                 byte ptr [eax + 0x29], 0

        $sequence_1 = { 413bd0 7511 48ffc1 4883c004 4883f904 7ce7 32c0 }
            // n = 7, score = 100
            //   413bd0               | dec                 eax
            //   7511                 | mov                 ecx, esi
            //   48ffc1               | dec                 eax
            //   4883c004             | mov                 eax, dword ptr [esi + 0x38]
            //   4883f904             | dec                 eax
            //   7ce7                 | mov                 ebx, dword ptr [eax]
            //   32c0                 | dec                 esp

        $sequence_2 = { 4803c1 48898398000000 488b4350 488b4818 48898bb0000000 0f28742470 440f28442460 }
            // n = 7, score = 100
            //   4803c1               | je                  0xecb
            //   48898398000000       | mov                 dword ptr [esp + 0x58], 0x40
            //   488b4350             | inc                 esp
            //   488b4818             | mov                 dword ptr [esp + 0x60], esp
            //   48898bb0000000       | dec                 esp
            //   0f28742470           | lea                 eax, [esp + 0x58]
            //   440f28442460         | dec                 eax

        $sequence_3 = { e8???????? 488d542450 b904010000 ff15???????? 4c8d05403b0300 488d4c2450 ba04010000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d542450           | dec                 eax
            //   b904010000           | mov                 dword ptr [ebx + 0x10], edi
            //   ff15????????         |                     
            //   4c8d05403b0300       | dec                 eax
            //   488d4c2450           | mov                 edx, dword ptr [esi + 8]
            //   ba04010000           | dec                 eax

        $sequence_4 = { 4c8d4e34 4c8b442458 488bd6 488b4e58 e8???????? 488d5614 488b4e50 }
            // n = 7, score = 100
            //   4c8d4e34             | dec                 eax
            //   4c8b442458           | mov                 eax, dword ptr [ecx + 0x1f0]
            //   488bd6               | inc                 ecx
            //   488b4e58             | push                esp
            //   e8????????           |                     
            //   488d5614             | dec                 eax
            //   488b4e50             | sub                 esp, 0x50

        $sequence_5 = { 488d5557 498d4c2408 e8???????? 488bd8 488d45b7 483bd8 7422 }
            // n = 7, score = 100
            //   488d5557             | jne                 0x45c
            //   498d4c2408           | dec                 eax
            //   e8????????           |                     
            //   488bd8               | arpl                cx, bx
            //   488d45b7             | inc                 ecx
            //   483bd8               | cmp                 dword ptr [esp + ebx*4 + 0x39570], 0
            //   7422                 | jne                 0x483

        $sequence_6 = { 488bf2 488bf9 488d91c0000000 488d4c2428 e8???????? 90 488dafa0000000 }
            // n = 7, score = 100
            //   488bf2               | cmp                 byte ptr [eax + 0x1d], 0
            //   488bf9               | jne                 0x6b
            //   488d91c0000000       | nop                 dword ptr [eax]
            //   488d4c2428           | dec                 eax
            //   e8????????           |                     
            //   90                   | mov                 eax, dword ptr [edi + 0x20]
            //   488dafa0000000       | dec                 eax

        $sequence_7 = { 4c894c2470 488b4508 4c3bc8 740f 418b4918 390e 7c07 }
            // n = 7, score = 100
            //   4c894c2470           | jl                  0x4a1
            //   488b4508             | dec                 eax
            //   4c3bc8               | lea                 ebx, [esp + 0x70]
            //   740f                 | jmp                 0x4b1
            //   418b4918             | dec                 eax
            //   390e                 | mov                 dword ptr [esp + 0x88], eax
            //   7c07                 | dec                 eax

        $sequence_8 = { 8d4801 488d93b8000000 8b02 3bc8 741b 8b83c0000000 488b8b88000000 }
            // n = 7, score = 100
            //   8d4801               | dec                 eax
            //   488d93b8000000       | mov                 dword ptr [esp + 0x58], esi
            //   8b02                 | dec                 ecx
            //   3bc8                 | mov                 esi, eax
            //   741b                 | dec                 eax
            //   8b83c0000000         | mov                 edi, edx
            //   488b8b88000000       | dec                 eax

        $sequence_9 = { 4489642460 4c8d442458 488d542460 488bc8 e8???????? eb03 498bc5 }
            // n = 7, score = 100
            //   4489642460           | sub                 esp, 0x20
            //   4c8d442458           | dec                 eax
            //   488d542460           | lea                 eax, [0x34487]
            //   488bc8               | mov                 ebx, edx
            //   e8????????           |                     
            //   eb03                 | dec                 eax
            //   498bc5               | mov                 edi, ecx

    condition:
        7 of them and filesize < 742400
}