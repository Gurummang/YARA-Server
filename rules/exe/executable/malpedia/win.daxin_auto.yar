rule win_daxin_auto {

    meta:
        atk_type = "win.daxin."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.daxin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.daxin"
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
        $sequence_0 = { 2bc2 d1f8 99 f7f9 }
            // n = 4, score = 400
            //   2bc2                 | sub                 eax, edx
            //   d1f8                 | sar                 eax, 1
            //   99                   | cdq                 
            //   f7f9                 | idiv                ecx

        $sequence_1 = { ff15???????? 488b0d???????? 483bcb 7458 895c2448 48895c2440 895c2438 }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   488b0d????????       |                     
            //   483bcb               | dec                 eax
            //   7458                 | and                 dword ptr [edi], 0
            //   895c2448             | xor                 edx, edx
            //   48895c2440           | inc                 ebp
            //   895c2438             | xor                 eax, eax

        $sequence_2 = { 751a baea050000 33c9 41b84d4b4353 }
            // n = 4, score = 300
            //   751a                 | mov                 edx, dword ptr [ebx + 0x28]
            //   baea050000           | and                 edx, 0x1f
            //   33c9                 | add                 eax, edx
            //   41b84d4b4353         | mov                 ecx, eax

        $sequence_3 = { ff15???????? 488983f8000000 4883a3d800000000 33d2 488d8bb0000000 448d4220 e8???????? }
            // n = 7, score = 300
            //   ff15????????         |                     
            //   488983f8000000       | mov                 eax, 0x53434b4d
            //   4883a3d800000000     | jne                 0x1c
            //   33d2                 | mov                 edx, 0x5ea
            //   488d8bb0000000       | xor                 ecx, ecx
            //   448d4220             | inc                 ecx
            //   e8????????           |                     

        $sequence_4 = { 83e21f 03c2 8bc8 83e01f c1f905 2bc2 488b5328 }
            // n = 7, score = 300
            //   83e21f               | mov                 dword ptr [esp + 0x38], ebx
            //   03c2                 | dec                 eax
            //   8bc8                 | cmp                 ecx, ebx
            //   83e01f               | je                  0x5a
            //   c1f905               | mov                 dword ptr [esp + 0x48], ebx
            //   2bc2                 | dec                 eax
            //   488b5328             | mov                 dword ptr [esp + 0x40], ebx

        $sequence_5 = { ff15???????? 488b0d???????? 48832700 33d2 4533c0 }
            // n = 5, score = 300
            //   ff15????????         |                     
            //   488b0d????????       |                     
            //   48832700             | and                 eax, 0x7f
            //   33d2                 | sub                 eax, edx
            //   4533c0               | dec                 eax

        $sequence_6 = { 83e27f 03c2 83e07f 2bc2 4863c8 8a8419c5010000 }
            // n = 6, score = 300
            //   83e27f               | inc                 ecx
            //   03c2                 | mov                 eax, 0x53434b4d
            //   83e07f               | add                 ebx, 0x20
            //   2bc2                 | and                 edx, 3
            //   4863c8               | and                 edx, 0x7f
            //   8a8419c5010000       | add                 eax, edx

        $sequence_7 = { 83e3e0 41b84d4b4353 83c320 83e203 03c2 895910 c1f802 }
            // n = 7, score = 300
            //   83e3e0               | and                 ebx, 0xffffffe0
            //   41b84d4b4353         | inc                 ecx
            //   83c320               | mov                 eax, 0x53434b4d
            //   83e203               | add                 ebx, 0x20
            //   03c2                 | and                 edx, 3
            //   895910               | add                 eax, edx
            //   c1f802               | mov                 dword ptr [ecx + 0x10], ebx

        $sequence_8 = { 88480d 8b5368 42 895368 }
            // n = 4, score = 100
            //   88480d               | mov                 byte ptr [eax + 5], cl
            //   8b5368               | mov                 ecx, dword ptr [ebx]
            //   42                   | mov                 eax, 7
            //   895368               | mov                 byte ptr [ecx + 6], 0

        $sequence_9 = { 884c241b c744241c08000000 c783b401000001000000 ff93f0020000 }
            // n = 4, score = 100
            //   884c241b             | inc                 edx
            //   c744241c08000000     | mov                 dword ptr [ebx + 0x68], edx
            //   c783b401000001000000     | mov    byte ptr [eax + 0xd], cl
            //   ff93f0020000         | mov                 edx, dword ptr [ebx + 0x68]

        $sequence_10 = { 884c2450 83c9ff 33c0 f2ae }
            // n = 4, score = 100
            //   884c2450             | mov                 byte ptr [eax + 0x2b], cl
            //   83c9ff               | add                 esi, 0xa1
            //   33c0                 | mov                 dword ptr [eax + 0xb0], edx
            //   f2ae                 | cmp                 esi, edx

        $sequence_11 = { 885004 33c0 f2ae f7d1 }
            // n = 4, score = 100
            //   885004               | mov                 byte ptr [esp + 0x1b], cl
            //   33c0                 | mov                 dword ptr [esp + 0x1c], 8
            //   f2ae                 | mov                 dword ptr [ebx + 0x1b4], 1
            //   f7d1                 | call                dword ptr [ebx + 0x2f0]

        $sequence_12 = { 88480d 8b4500 50 ff5018 }
            // n = 4, score = 100
            //   88480d               | idiv                ecx
            //   8b4500               | cdq                 
            //   50                   | sub                 eax, edx
            //   ff5018               | sar                 eax, 1

        $sequence_13 = { 884805 8b0b b807000000 c6410600 8b4b04 3bc8 }
            // n = 6, score = 100
            //   884805               | cdq                 
            //   8b0b                 | sub                 eax, edx
            //   b807000000           | sar                 eax, 1
            //   c6410600             | cdq                 
            //   8b4b04               | idiv                ecx
            //   3bc8                 | mov                 al, byte ptr [ebx + edx]

        $sequence_14 = { 88482b 81c6a1000000 8990b0000000 3bf2 }
            // n = 4, score = 100
            //   88482b               | push                eax
            //   81c6a1000000         | call                dword ptr [eax + 0x18]
            //   8990b0000000         | mov                 edx, dword ptr [ebp + 0xa8]
            //   3bf2                 | mov                 byte ptr [eax + 0xd], cl

    condition:
        7 of them and filesize < 3475456
}