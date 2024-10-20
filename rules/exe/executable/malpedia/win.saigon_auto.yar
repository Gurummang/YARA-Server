rule win_saigon_auto {

    meta:
        atk_type = "win.saigon."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.saigon."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.saigon"
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
        $sequence_0 = { 7508 ff15???????? 8bd8 4c8d5c2450 8bc3 498b5b20 498b6b28 }
            // n = 7, score = 200
            //   7508                 | xor                 edx, edx
            //   ff15????????         |                     
            //   8bd8                 | inc                 ebp
            //   4c8d5c2450           | xor                 eax, eax
            //   8bc3                 | inc                 ecx
            //   498b5b20             | mov                 edx, ebp
            //   498b6b28             | xor                 ecx, ecx

        $sequence_1 = { 4889442440 488364243800 488364243000 4533c0 488bd3 33c9 }
            // n = 6, score = 200
            //   4889442440           | dec                 eax
            //   488364243800         | mov                 dword ptr [esp + 0x48], eax
            //   488364243000         | dec                 eax
            //   4533c0               | lea                 eax, [esp + 0x80]
            //   488bd3               | xor                 eax, eax
            //   33c9                 | dec                 eax

        $sequence_2 = { ff15???????? 33ed 488bcb 85c0 }
            // n = 4, score = 200
            //   ff15????????         |                     
            //   33ed                 | mov                 ebx, eax
            //   488bcb               | je                  0x90
            //   85c0                 | dec                 eax

        $sequence_3 = { 7459 f60301 742c 418bcf 488bd0 4903cc e8???????? }
            // n = 7, score = 200
            //   7459                 | cmp                 eax, ebx
            //   f60301               | dec                 eax
            //   742c                 | mov                 edi, eax
            //   418bcf               | je                  0x59c
            //   488bd0               | inc                 esp
            //   4903cc               | lea                 eax, [eax + eax]
            //   e8????????           |                     

        $sequence_4 = { 488b0d???????? 4c8bc7 33d2 8bd8 ff15???????? eb1e }
            // n = 6, score = 200
            //   488b0d????????       |                     
            //   4c8bc7               | inc                 ecx
            //   33d2                 | cmp                 ebx, ebx
            //   8bd8                 | jne                 0x7ba
            //   ff15????????         |                     
            //   eb1e                 | xor                 ebx, ebx

        $sequence_5 = { 4156 4157 4883ec60 4c8bea 488d50c8 4d8bf9 e8???????? }
            // n = 7, score = 200
            //   4156                 | lea                 edx, [0xe6ea]
            //   4157                 | dec                 esp
            //   4883ec60             | mov                 ecx, esi
            //   4c8bea               | lea                 ebx, [eax + 7]
            //   488d50c8             | dec                 eax
            //   4d8bf9               | mov                 ecx, esi
            //   e8????????           |                     

        $sequence_6 = { ffd0 85c0 790e 8bc8 }
            // n = 4, score = 200
            //   ffd0                 | test                eax, eax
            //   85c0                 | mov                 ebx, eax
            //   790e                 | js                  0x486
            //   8bc8                 | dec                 eax

        $sequence_7 = { 4c8d8584020000 488d8c2460060000 448bcb 418bd6 e8???????? }
            // n = 5, score = 200
            //   4c8d8584020000       | lea                 edx, [esp + 0x68]
            //   488d8c2460060000     | dec                 eax
            //   448bcb               | mov                 eax, dword ptr [ecx]
            //   418bd6               | call                dword ptr [eax + 0x58]
            //   e8????????           |                     

        $sequence_8 = { 33d2 8d440036 448bc0 448be0 ff15???????? }
            // n = 5, score = 200
            //   33d2                 | jne                 0x420
            //   8d440036             | test                esi, esi
            //   448bc0               | mov                 ebx, eax
            //   448be0               | test                eax, eax
            //   ff15????????         |                     

        $sequence_9 = { 8d4f01 448bcf 4c8bc6 894c2428 33c9 33d2 }
            // n = 6, score = 200
            //   8d4f01               | dec                 eax
            //   448bcf               | arpl                word ptr [edi + 0x3c], dx
            //   4c8bc6               | dec                 eax
            //   894c2428             | lea                 eax, [esp + 0x70]
            //   33c9                 | dec                 eax
            //   33d2                 | mov                 ecx, edi

    condition:
        7 of them and filesize < 147456
}