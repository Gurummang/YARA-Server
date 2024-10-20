rule win_shifu_auto {

    meta:
        atk_type = "win.shifu."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.shifu."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shifu"
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
        $sequence_0 = { 85c0 740d 57 6a1b ba???????? }
            // n = 5, score = 100
            //   85c0                 | test                eax, eax
            //   740d                 | je                  0xf
            //   57                   | push                edi
            //   6a1b                 | push                0x1b
            //   ba????????           |                     

        $sequence_1 = { 6a24 ff7508 ffd6 53 8d45f0 50 }
            // n = 6, score = 100
            //   6a24                 | push                0x24
            //   ff7508               | push                dword ptr [ebp + 8]
            //   ffd6                 | call                esi
            //   53                   | push                ebx
            //   8d45f0               | lea                 eax, [ebp - 0x10]
            //   50                   | push                eax

        $sequence_2 = { 83651800 8d941a00010000 895508 8b5510 0fbe1410 89550c 85c9 }
            // n = 7, score = 100
            //   83651800             | and                 dword ptr [ebp + 0x18], 0
            //   8d941a00010000       | lea                 edx, [edx + ebx + 0x100]
            //   895508               | mov                 dword ptr [ebp + 8], edx
            //   8b5510               | mov                 edx, dword ptr [ebp + 0x10]
            //   0fbe1410             | movsx               edx, byte ptr [eax + edx]
            //   89550c               | mov                 dword ptr [ebp + 0xc], edx
            //   85c9                 | test                ecx, ecx

        $sequence_3 = { 740c e8???????? 8325????????00 8d85fcfeffff e8???????? }
            // n = 5, score = 100
            //   740c                 | je                  0xe
            //   e8????????           |                     
            //   8325????????00       |                     
            //   8d85fcfeffff         | lea                 eax, [ebp - 0x104]
            //   e8????????           |                     

        $sequence_4 = { 50 ff75f4 ff15???????? 85c0 7511 ff75f0 8d443701 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   ff75f4               | push                dword ptr [ebp - 0xc]
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7511                 | jne                 0x13
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   8d443701             | lea                 eax, [edi + esi + 1]

        $sequence_5 = { 668985a2fcffff b8170b0000 66898578fcffff 6a14 58 6689857afcffff 8b4348 }
            // n = 7, score = 100
            //   668985a2fcffff       | mov                 word ptr [ebp - 0x35e], ax
            //   b8170b0000           | mov                 eax, 0xb17
            //   66898578fcffff       | mov                 word ptr [ebp - 0x388], ax
            //   6a14                 | push                0x14
            //   58                   | pop                 eax
            //   6689857afcffff       | mov                 word ptr [ebp - 0x386], ax
            //   8b4348               | mov                 eax, dword ptr [ebx + 0x48]

        $sequence_6 = { 83c102 836d0c02 eb2d 8bd9 8b4f2c 2bd8 035de8 }
            // n = 7, score = 100
            //   83c102               | add                 ecx, 2
            //   836d0c02             | sub                 dword ptr [ebp + 0xc], 2
            //   eb2d                 | jmp                 0x2f
            //   8bd9                 | mov                 ebx, ecx
            //   8b4f2c               | mov                 ecx, dword ptr [edi + 0x2c]
            //   2bd8                 | sub                 ebx, eax
            //   035de8               | add                 ebx, dword ptr [ebp - 0x18]

        $sequence_7 = { 8975e4 6a0c 58 e8???????? 8965e8 8bfc 3bfe }
            // n = 7, score = 100
            //   8975e4               | mov                 dword ptr [ebp - 0x1c], esi
            //   6a0c                 | push                0xc
            //   58                   | pop                 eax
            //   e8????????           |                     
            //   8965e8               | mov                 dword ptr [ebp - 0x18], esp
            //   8bfc                 | mov                 edi, esp
            //   3bfe                 | cmp                 edi, esi

        $sequence_8 = { 33c0 5e c9 c20c00 55 8bec 85c9 }
            // n = 7, score = 100
            //   33c0                 | xor                 eax, eax
            //   5e                   | pop                 esi
            //   c9                   | leave               
            //   c20c00               | ret                 0xc
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   85c9                 | test                ecx, ecx

        $sequence_9 = { 56 8d85e8feffff 53 50 ff15???????? 8d85e8feffff 83c410 }
            // n = 7, score = 100
            //   56                   | push                esi
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8d85e8feffff         | lea                 eax, [ebp - 0x118]
            //   83c410               | add                 esp, 0x10

    condition:
        7 of them and filesize < 344064
}