rule win_sage_ransom_auto {

    meta:
        atk_type = "win.sage_ransom."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.sage_ransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sage_ransom"
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
        $sequence_0 = { 57 56 68???????? e8???????? 83c408 6a00 6a00 }
            // n = 7, score = 300
            //   57                   | push                edi
            //   56                   | push                esi
            //   68????????           |                     
            //   e8????????           |                     
            //   83c408               | add                 esp, 8
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_1 = { 8b74246c 57 c7442408adde9e5a b908000000 8d7c240c f3a5 8b742478 }
            // n = 7, score = 300
            //   8b74246c             | mov                 esi, dword ptr [esp + 0x6c]
            //   57                   | push                edi
            //   c7442408adde9e5a     | mov                 dword ptr [esp + 8], 0x5a9edead
            //   b908000000           | mov                 ecx, 8
            //   8d7c240c             | lea                 edi, [esp + 0xc]
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8b742478             | mov                 esi, dword ptr [esp + 0x78]

        $sequence_2 = { 6a02 ff15???????? 8bf0 8d471c }
            // n = 4, score = 300
            //   6a02                 | push                2
            //   ff15????????         |                     
            //   8bf0                 | mov                 esi, eax
            //   8d471c               | lea                 eax, [edi + 0x1c]

        $sequence_3 = { 55 56 894c243c ff15???????? 83f8ff 7541 56 }
            // n = 7, score = 300
            //   55                   | push                ebp
            //   56                   | push                esi
            //   894c243c             | mov                 dword ptr [esp + 0x3c], ecx
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   7541                 | jne                 0x43
            //   56                   | push                esi

        $sequence_4 = { 56 57 6af5 ff15???????? 8b15???????? 83c204 52 }
            // n = 7, score = 300
            //   56                   | push                esi
            //   57                   | push                edi
            //   6af5                 | push                -0xb
            //   ff15????????         |                     
            //   8b15????????         |                     
            //   83c204               | add                 edx, 4
            //   52                   | push                edx

        $sequence_5 = { 68e0930400 ffd6 6a02 e8???????? 83c404 68c0270900 }
            // n = 6, score = 300
            //   68e0930400           | push                0x493e0
            //   ffd6                 | call                esi
            //   6a02                 | push                2
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   68c0270900           | push                0x927c0

        $sequence_6 = { 0facf014 89442420 c1ee14 8bc6 }
            // n = 4, score = 300
            //   0facf014             | shrd                eax, esi, 0x14
            //   89442420             | mov                 dword ptr [esp + 0x20], eax
            //   c1ee14               | shr                 esi, 0x14
            //   8bc6                 | mov                 eax, esi

        $sequence_7 = { 83c438 833d????????00 7513 e8???????? 50 }
            // n = 5, score = 300
            //   83c438               | add                 esp, 0x38
            //   833d????????00       |                     
            //   7513                 | jne                 0x15
            //   e8????????           |                     
            //   50                   | push                eax

        $sequence_8 = { 01410c 8b4310 014110 8b4314 }
            // n = 4, score = 200
            //   01410c               | add                 dword ptr [ecx + 0xc], eax
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]
            //   014110               | add                 dword ptr [ecx + 0x10], eax
            //   8b4314               | mov                 eax, dword ptr [ebx + 0x14]

        $sequence_9 = { 013c13 83c102 46 ebd3 }
            // n = 4, score = 200
            //   013c13               | add                 dword ptr [ebx + edx], edi
            //   83c102               | add                 ecx, 2
            //   46                   | inc                 esi
            //   ebd3                 | jmp                 0xffffffd5

        $sequence_10 = { 014114 8b4318 014118 8b431c }
            // n = 4, score = 200
            //   014114               | add                 dword ptr [ecx + 0x14], eax
            //   8b4318               | mov                 eax, dword ptr [ebx + 0x18]
            //   014118               | add                 dword ptr [ecx + 0x18], eax
            //   8b431c               | mov                 eax, dword ptr [ebx + 0x1c]

        $sequence_11 = { 0101 8b4304 014104 8b4308 014108 }
            // n = 5, score = 200
            //   0101                 | add                 dword ptr [ecx], eax
            //   8b4304               | mov                 eax, dword ptr [ebx + 4]
            //   014104               | add                 dword ptr [ecx + 4], eax
            //   8b4308               | mov                 eax, dword ptr [ebx + 8]
            //   014108               | add                 dword ptr [ecx + 8], eax

        $sequence_12 = { 891c24 89442404 e8???????? 31d2 3955dc 0f86df000000 }
            // n = 6, score = 200
            //   891c24               | mov                 dword ptr [esp], ebx
            //   89442404             | mov                 dword ptr [esp + 4], eax
            //   e8????????           |                     
            //   31d2                 | xor                 edx, edx
            //   3955dc               | cmp                 dword ptr [ebp - 0x24], edx
            //   0f86df000000         | jbe                 0xe5

        $sequence_13 = { 014110 8b4314 014114 8b4318 }
            // n = 4, score = 200
            //   014110               | add                 dword ptr [ecx + 0x10], eax
            //   8b4314               | mov                 eax, dword ptr [ebx + 0x14]
            //   014114               | add                 dword ptr [ecx + 0x14], eax
            //   8b4318               | mov                 eax, dword ptr [ebx + 0x18]

        $sequence_14 = { 0119 117104 83c110 83c210 }
            // n = 4, score = 200
            //   0119                 | add                 dword ptr [ecx], ebx
            //   117104               | adc                 dword ptr [ecx + 4], esi
            //   83c110               | add                 ecx, 0x10
            //   83c210               | add                 edx, 0x10

        $sequence_15 = { 014108 8b430c 01410c 8b4310 }
            // n = 4, score = 200
            //   014108               | add                 dword ptr [ecx + 8], eax
            //   8b430c               | mov                 eax, dword ptr [ebx + 0xc]
            //   01410c               | add                 dword ptr [ecx + 0xc], eax
            //   8b4310               | mov                 eax, dword ptr [ebx + 0x10]

    condition:
        7 of them and filesize < 335872
}