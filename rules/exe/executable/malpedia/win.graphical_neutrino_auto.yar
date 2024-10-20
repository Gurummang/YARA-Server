rule win_graphical_neutrino_auto {

    meta:
        atk_type = "win.graphical_neutrino."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.graphical_neutrino."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.graphical_neutrino"
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
        $sequence_0 = { 4489c7 4889f2 48c7410800000000 4531c0 4889d9 4c8d6c2450 e8???????? }
            // n = 7, score = 500
            //   4489c7               | dec                 ecx
            //   4889f2               | mov                 ecx, esi
            //   48c7410800000000     | inc                 ecx
            //   4531c0               | mov                 eax, 0x10
            //   4889d9               | dec                 eax
            //   4c8d6c2450           | lea                 edx, [0x11ad8]
            //   e8????????           |                     

        $sequence_1 = { ff15???????? 4883fe10 7f1c 41b828400000 }
            // n = 4, score = 500
            //   ff15????????         |                     
            //   4883fe10             | lea                 ecx, [0x4019d]
            //   7f1c                 | test                eax, eax
            //   41b828400000         | jne                 0x6c4

        $sequence_2 = { 48c78424c800000002000000 48898424c0000000 e8???????? 4c8da424c0000000 488d842460050000 48c78424c800000002000000 }
            // n = 6, score = 500
            //   48c78424c800000002000000     | pop    esi
            //   48898424c0000000     | dec                 eax
            //   e8????????           |                     
            //   4c8da424c0000000     | mov                 eax, dword ptr [esp + 0x1a8]
            //   488d842460050000     | dec                 esp
            //   48c78424c800000002000000     | mov    dword ptr [esp + 0x20], edi

        $sequence_3 = { eb07 b001 80fa09 7478 }
            // n = 4, score = 500
            //   eb07                 | dec                 eax
            //   b001                 | lea                 ecx, [0xc37a]
            //   80fa09               | jne                 0xde9
            //   7478                 | inc                 ecx

        $sequence_4 = { 8806 488d4602 885601 eb2d b964000000 }
            // n = 5, score = 500
            //   8806                 | dec                 eax
            //   488d4602             | lea                 ecx, [0x3dedc]
            //   885601               | dec                 eax
            //   eb2d                 | lea                 eax, [0x3ded0]
            //   b964000000           | dec                 eax

        $sequence_5 = { 53 4883ec20 4c8b6108 4889cb 4c3b6110 740f }
            // n = 6, score = 500
            //   53                   | inc                 ecx
            //   4883ec20             | mov                 eax, 0x1970
            //   4c8b6108             | dec                 eax
            //   4889cb               | lea                 edx, [0x11a5c]
            //   4c3b6110             | dec                 eax
            //   740f                 | lea                 ecx, [0x121dd]

        $sequence_6 = { ebcc 31db 4c89ea 4c89e1 4189de ffc3 }
            // n = 6, score = 500
            //   ebcc                 | lea                 ecx, [0x3f12b]
            //   31db                 | dec                 eax
            //   4c89ea               | lea                 edx, [0x3f11f]
            //   4c89e1               | dec                 esp
            //   4189de               | mov                 ecx, esp
            //   ffc3                 | dec                 eax

        $sequence_7 = { 7430 c605????????01 31c0 8a1403 881406 48ffc0 4883f81f }
            // n = 7, score = 500
            //   7430                 | mov                 ecx, dword ptr [esp + 0x38]
            //   c605????????01       |                     
            //   31c0                 | dec                 eax
            //   8a1403               | lea                 ecx, [0x3d609]
            //   881406               | dec                 eax
            //   48ffc0               | lea                 ecx, [0xffffb571]
            //   4883f81f             | dec                 eax

        $sequence_8 = { 4155 4154 53 4883ec20 c60100 4889cb 4989d5 }
            // n = 7, score = 500
            //   4155                 | lea                 ecx, [0xffff9fa4]
            //   4154                 | dec                 eax
            //   53                   | lea                 ecx, [0x3bd8d]
            //   4883ec20             | dec                 eax
            //   c60100               | lea                 ecx, [0x3bf9d]
            //   4889cb               | dec                 eax
            //   4989d5               | lea                 ecx, [0x3bf89]

        $sequence_9 = { bd07000000 eb32 41b9a0860100 bd06000000 eb25 41b910270000 bd05000000 }
            // n = 7, score = 500
            //   bd07000000           | add                 esp, 0x28
            //   eb32                 | xor                 edx, edx
            //   41b9a0860100         | dec                 esp
            //   bd06000000           | mov                 ecx, dword ptr [esp + 0x40]
            //   eb25                 | dec                 eax
            //   41b910270000         | div                 dword ptr [esp + 0x48]
            //   bd05000000           | dec                 ecx

    condition:
        7 of them and filesize < 674816
}