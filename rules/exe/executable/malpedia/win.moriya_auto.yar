rule win_moriya_auto {

    meta:
        atk_type = "win.moriya."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.moriya."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moriya"
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
        $sequence_0 = { 8bce ff15???????? 4533c0 488d0dcf260000 33d2 }
            // n = 5, score = 100
            //   8bce                 | add                 edx, 4
            //   ff15????????         |                     
            //   4533c0               | dec                 eax
            //   488d0dcf260000       | mov                 esi, eax
            //   33d2                 | dec                 eax

        $sequence_1 = { 488bfa 4c8d051c0d0000 33d2 8d5a4d 8bcb ff15???????? 4c8d05280d0000 }
            // n = 7, score = 100
            //   488bfa               | js                  0x1725
            //   4c8d051c0d0000       | dec                 eax
            //   33d2                 | lea                 esi, [0x250d]
            //   8d5a4d               | dec                 eax
            //   8bcb                 | or                  eax, 0xffffffff
            //   ff15????????         |                     
            //   4c8d05280d0000       | dec                 eax

        $sequence_2 = { 8b4f10 8d81fffeffff 83f801 7608 81f910010000 7564 ba28000000 }
            // n = 7, score = 100
            //   8b4f10               | xor                 edx, edx
            //   8d81fffeffff         | inc                 ecx
            //   83f801               | mov                 ecx, esi
            //   7608                 | test                eax, eax
            //   81f910010000         | and                 dword ptr [ebx + 0x18], 0xfffffffe
            //   7564                 | dec                 eax
            //   ba28000000           | mov                 ecx, dword ptr [esp + 0x30]

        $sequence_3 = { 448d724d 418bce 0f114dc0 0f1145d0 ff15???????? }
            // n = 5, score = 100
            //   448d724d             | mov                 ecx, dword ptr [ebx + 0x38]
            //   418bce               | dec                 eax
            //   0f114dc0             | mov                 dword ptr [esi + 8], ecx
            //   0f1145d0             | dec                 eax
            //   ff15????????         |                     

        $sequence_4 = { 4885c0 7509 4c8d05b60f0000 eba3 4c8d05dd0f0000 ff15???????? }
            // n = 6, score = 100
            //   4885c0               | cmp                 byte ptr [edi + 0x44], bl
            //   7509                 | je                  0xf2
            //   4c8d05b60f0000       | dec                 esp
            //   eba3                 | mov                 ebp, dword ptr [edi + 0x70]
            //   4c8d05dd0f0000       | mov                 ecx, dword ptr [edi + 0x38]
            //   ff15????????         |                     

        $sequence_5 = { ff15???????? 488b8c2498000000 4885c9 7405 e8???????? }
            // n = 5, score = 100
            //   ff15????????         |                     
            //   488b8c2498000000     | dec                 ecx
            //   4885c9               | mov                 ebx, eax
            //   7405                 | dec                 eax
            //   e8????????           |                     

        $sequence_6 = { ff15???????? 8bc3 488b8c2488000000 4833cc e8???????? 4881c490000000 415f }
            // n = 7, score = 100
            //   ff15????????         |                     
            //   8bc3                 | dec                 eax
            //   488b8c2488000000     | mov                 ecx, dword ptr [ebx + 8]
            //   4833cc               | dec                 eax
            //   e8????????           |                     
            //   4881c490000000       | test                ecx, ecx
            //   415f                 | je                  0x2d8

        $sequence_7 = { 33d2 ff15???????? 4883673800 488b0d???????? 4885c9 7467 }
            // n = 6, score = 100
            //   33d2                 | dec                 eax
            //   ff15????????         |                     
            //   4883673800           | lea                 ecx, [0x2501]
            //   488b0d????????       |                     
            //   4885c9               | dec                 eax
            //   7467                 | lea                 eax, [0xfffff8a7]

        $sequence_8 = { 4c8bc3 49ffc0 42803c0000 75f6 488b15???????? }
            // n = 5, score = 100
            //   4c8bc3               | mov                 edx, dword ptr [edi + 0x30]
            //   49ffc0               | cmp                 dword ptr [edx + 0x30], ebx
            //   42803c0000           | jl                  0x27c
            //   75f6                 | dec                 esp
            //   488b15????????       |                     

        $sequence_9 = { 488b0d???????? 4885c9 7405 e8???????? 8bc7 488b4df0 }
            // n = 6, score = 100
            //   488b0d????????       |                     
            //   4885c9               | add                 ecx, 0x40
            //   7405                 | movdqu              xmm0, xmmword ptr [ecx + edx - 0x20]
            //   e8????????           |                     
            //   8bc7                 | movdqu              xmm1, xmmword ptr [ecx + edx - 0x10]
            //   488b4df0             | movntdq             xmmword ptr [ecx - 0x10], xmm0

    condition:
        7 of them and filesize < 58368
}