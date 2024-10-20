rule win_royal_ransom_auto {

    meta:
        atk_type = "win.royal_ransom."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.royal_ransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royal_ransom"
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
        $sequence_0 = { 752f e8???????? 4c8d05d60c1400 ba8b010000 488d0d320c1400 e8???????? 4533c0 }
            // n = 7, score = 100
            //   752f                 | lea                 edx, [0x143571]
            //   e8????????           |                     
            //   4c8d05d60c1400       | inc                 ebp
            //   ba8b010000           | xor                 ecx, ecx
            //   488d0d320c1400       | test                eax, eax
            //   e8????????           |                     
            //   4533c0               | jle                 0x78b

        $sequence_1 = { e9???????? 2bc3 488d0d2df4dfff 488b8ce9d02c2d00 8064f93dfd f7d8 1ac0 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   2bc3                 | dec                 eax
            //   488d0d2df4dfff       | arpl                di, ax
            //   488b8ce9d02c2d00     | dec                 eax
            //   8064f93dfd           | lea                 ebx, [eax*8]
            //   f7d8                 | dec                 eax
            //   1ac0                 | add                 ecx, ebx

        $sequence_2 = { e8???????? 33c0 e9???????? 488b4820 e8???????? 85c0 0f8497020000 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   33c0                 | inc                 ecx
            //   e9????????           |                     
            //   488b4820             | mov                 eax, 0xa
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   0f8497020000         | mov                 edx, esi

        $sequence_3 = { e8???????? 488d4e24 448bc8 4c8d0579a80d00 ba09000000 e8???????? 488bcb }
            // n = 7, score = 100
            //   e8????????           |                     
            //   488d4e24             | inc                 ebp
            //   448bc8               | xor                 ecx, dword ptr [edi + ecx*4 + 0x25fb80]
            //   4c8d0579a80d00       | inc                 esp
            //   ba09000000           | mov                 eax, ebx
            //   e8????????           |                     
            //   488bcb               | mov                 dword ptr [esp + 0x20], 0xffffffff

        $sequence_4 = { 8bc2 896c2444 418bfe 83fa02 7d3e e8???????? 4c8d05e7a90f00 }
            // n = 7, score = 100
            //   8bc2                 | dec                 eax
            //   896c2444             | mov                 ecx, edi
            //   418bfe               | dec                 eax
            //   83fa02               | test                eax, eax
            //   7d3e                 | je                  0xe0e
            //   e8????????           |                     
            //   4c8d05e7a90f00       | dec                 eax

        $sequence_5 = { 488d1507b51300 41b893040000 e8???????? 41b894040000 488d15efb41300 488bcf e8???????? }
            // n = 7, score = 100
            //   488d1507b51300       | dec                 esp
            //   41b893040000         | lea                 eax, [0xfa846]
            //   e8????????           |                     
            //   41b894040000         | mov                 edx, 0x69
            //   488d15efb41300       | dec                 eax
            //   488bcf               | lea                 ecx, [0xfa7fa]
            //   e8????????           |                     

        $sequence_6 = { e8???????? baa6000000 4c89742420 4c8bcd 4c8d05f3a80e00 8d4a93 e8???????? }
            // n = 7, score = 100
            //   e8????????           |                     
            //   baa6000000           | dec                 eax
            //   4c89742420           | lea                 ecx, [0xd9b5a]
            //   4c8bcd               | dec                 eax
            //   4c8d05f3a80e00       | cmp                 eax, esi
            //   8d4a93               | jne                 0xe0d
            //   e8????????           |                     

        $sequence_7 = { 754a e8???????? 4c8d054e820d00 baa2000000 488d0df2810d00 e8???????? 4533c0 }
            // n = 7, score = 100
            //   754a                 | lea                 edx, [0x146338]
            //   e8????????           |                     
            //   4c8d054e820d00       | dec                 eax
            //   baa2000000           | sub                 ebx, edi
            //   488d0df2810d00       | test                eax, eax
            //   e8????????           |                     
            //   4533c0               | jne                 0x362

        $sequence_8 = { b828000000 e8???????? 482be0 488d15fc4fffff 488d0d5de62000 e8???????? 33c9 }
            // n = 7, score = 100
            //   b828000000           | pop                 edi
            //   e8????????           |                     
            //   482be0               | ret                 
            //   488d15fc4fffff       | inc                 ecx
            //   488d0d5de62000       | mov                 eax, 0x3c
            //   e8????????           |                     
            //   33c9                 | dec                 eax

        $sequence_9 = { e8???????? 85c0 7437 488d05297a0000 4c89742430 4889442428 4c8d0d485c0e00 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   85c0                 | dec                 eax
            //   7437                 | mov                 ebx, ecx
            //   488d05297a0000       | inc                 esp
            //   4c89742430           | lea                 eax, [eax + 0x6d]
            //   4889442428           | dec                 eax
            //   4c8d0d485c0e00       | mov                 ecx, dword ptr [ecx + 0x20]

    condition:
        7 of them and filesize < 6235136
}