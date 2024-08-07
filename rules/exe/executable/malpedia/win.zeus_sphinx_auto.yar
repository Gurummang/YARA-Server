rule win_zeus_sphinx_auto {

    meta:
        atk_type = "win.zeus_sphinx."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.zeus_sphinx."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeus_sphinx"
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
        $sequence_0 = { 50 e8???????? 891c24 89c6 e8???????? 83c410 8d65f4 }
            // n = 7, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   891c24               | mov                 dword ptr [esp], ebx
            //   89c6                 | mov                 esi, eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   8d65f4               | lea                 esp, [ebp - 0xc]

        $sequence_1 = { 50 e8???????? 83c414 68???????? e8???????? c70424???????? }
            // n = 6, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   68????????           |                     
            //   e8????????           |                     
            //   c70424????????       |                     

        $sequence_2 = { 50 e8???????? 83c410 c74604ffffffff 897508 }
            // n = 5, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   c74604ffffffff       | mov                 dword ptr [esi + 4], 0xffffffff
            //   897508               | mov                 dword ptr [ebp + 8], esi

        $sequence_3 = { 50 e8???????? 83c430 85c0 7e0c }
            // n = 5, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c430               | add                 esp, 0x30
            //   85c0                 | test                eax, eax
            //   7e0c                 | jle                 0xe

        $sequence_4 = { 52 52 8b6c2444 55 50 e8???????? 8944245c }
            // n = 7, score = 400
            //   52                   | push                edx
            //   52                   | push                edx
            //   8b6c2444             | mov                 ebp, dword ptr [esp + 0x44]
            //   55                   | push                ebp
            //   50                   | push                eax
            //   e8????????           |                     
            //   8944245c             | mov                 dword ptr [esp + 0x5c], eax

        $sequence_5 = { 50 e8???????? 84c0 745f 8d442414 }
            // n = 5, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   84c0                 | test                al, al
            //   745f                 | je                  0x61
            //   8d442414             | lea                 eax, [esp + 0x14]

        $sequence_6 = { 50 e8???????? 83c420 48 }
            // n = 4, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c420               | add                 esp, 0x20
            //   48                   | dec                 eax

        $sequence_7 = { 50 e8???????? 83c418 68???????? 68???????? }
            // n = 5, score = 400
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c418               | add                 esp, 0x18
            //   68????????           |                     
            //   68????????           |                     

        $sequence_8 = { 01fc eb98 035e14 8ade }
            // n = 4, score = 100
            //   01fc                 | add                 esp, edi
            //   eb98                 | jmp                 0xffffff9a
            //   035e14               | add                 ebx, dword ptr [esi + 0x14]
            //   8ade                 | mov                 bl, dh

        $sequence_9 = { 010c02 3bf7 0f85f0f50000 e9???????? }
            // n = 4, score = 100
            //   010c02               | add                 dword ptr [edx + eax], ecx
            //   3bf7                 | cmp                 esi, edi
            //   0f85f0f50000         | jne                 0xf5f6
            //   e9????????           |                     

        $sequence_10 = { 003b c09bdbe23ea11c 695600663ec700 de07 }
            // n = 4, score = 100
            //   003b                 | add                 byte ptr [ebx], bh
            //   c09bdbe23ea11c       | rcr                 byte ptr [ebx - 0x5ec11d25], 0x1c
            //   695600663ec700       | imul                edx, dword ptr [esi], 0xc73e66
            //   de07                 | fiadd               word ptr [edi]

        $sequence_11 = { 0303 50 ff550c 8b3e }
            // n = 4, score = 100
            //   0303                 | add                 eax, dword ptr [ebx]
            //   50                   | push                eax
            //   ff550c               | call                dword ptr [ebp + 0xc]
            //   8b3e                 | mov                 edi, dword ptr [esi]

        $sequence_12 = { 010d???????? 60 5a 98 }
            // n = 4, score = 100
            //   010d????????         |                     
            //   60                   | pushal              
            //   5a                   | pop                 edx
            //   98                   | cwde                

        $sequence_13 = { 020a 42 1af6 af }
            // n = 4, score = 100
            //   020a                 | add                 cl, byte ptr [edx]
            //   42                   | inc                 edx
            //   1af6                 | sbb                 dh, dh
            //   af                   | scasd               eax, dword ptr es:[edi]

        $sequence_14 = { 0162c9 cf 0c06 3c3e }
            // n = 4, score = 100
            //   0162c9               | add                 dword ptr [edx - 0x37], esp
            //   cf                   | iretd               
            //   0c06                 | or                  al, 6
            //   3c3e                 | cmp                 al, 0x3e

        $sequence_15 = { 0008 d7 9f b2d3 }
            // n = 4, score = 100
            //   0008                 | add                 byte ptr [eax], cl
            //   d7                   | xlatb               
            //   9f                   | lahf                
            //   b2d3                 | mov                 dl, 0xd3

    condition:
        7 of them and filesize < 3268608
}