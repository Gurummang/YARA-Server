rule win_polyglot_ransom_auto {

    meta:
        atk_type = "win.polyglot_ransom."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.polyglot_ransom."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.polyglot_ransom"
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
        $sequence_0 = { ff74244c e8???????? 8944241c 894c2448 6a07 895c2450 }
            // n = 6, score = 100
            //   ff74244c             | push                dword ptr [esp + 0x4c]
            //   e8????????           |                     
            //   8944241c             | mov                 dword ptr [esp + 0x1c], eax
            //   894c2448             | mov                 dword ptr [esp + 0x48], ecx
            //   6a07                 | push                7
            //   895c2450             | mov                 dword ptr [esp + 0x50], ebx

        $sequence_1 = { 6a30 e8???????? 59 59 8d4d80 51 6801010000 }
            // n = 7, score = 100
            //   6a30                 | push                0x30
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8d4d80               | lea                 ecx, [ebp - 0x80]
            //   51                   | push                ecx
            //   6801010000           | push                0x101

        $sequence_2 = { ff5004 83c328 ff4d10 75ad ff75f0 ff15???????? }
            // n = 6, score = 100
            //   ff5004               | call                dword ptr [eax + 4]
            //   83c328               | add                 ebx, 0x28
            //   ff4d10               | dec                 dword ptr [ebp + 0x10]
            //   75ad                 | jne                 0xffffffaf
            //   ff75f0               | push                dword ptr [ebp - 0x10]
            //   ff15????????         |                     

        $sequence_3 = { be???????? 66f7c30040 6a04 5a 747a 6681fb0b40 756c }
            // n = 7, score = 100
            //   be????????           |                     
            //   66f7c30040           | test                bx, 0x4000
            //   6a04                 | push                4
            //   5a                   | pop                 edx
            //   747a                 | je                  0x7c
            //   6681fb0b40           | cmp                 bx, 0x400b
            //   756c                 | jne                 0x6e

        $sequence_4 = { 50 68???????? e8???????? 8b85f0fdffff 59 59 8b08 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   68????????           |                     
            //   e8????????           |                     
            //   8b85f0fdffff         | mov                 eax, dword ptr [ebp - 0x210]
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8b08                 | mov                 ecx, dword ptr [eax]

        $sequence_5 = { 627265 206f20 656c 696d696e617220 61 7263 6869766f73 }
            // n = 7, score = 100
            //   627265               | bound               esi, qword ptr [edx + 0x65]
            //   206f20               | and                 byte ptr [edi + 0x20], ch
            //   656c                 | insb                byte ptr es:[edi], dx
            //   696d696e617220       | imul                ebp, dword ptr [ebp + 0x69], 0x2072616e
            //   61                   | popal               
            //   7263                 | jb                  0x65
            //   6869766f73           | push                0x736f7669

        $sequence_6 = { eb4f 8bf3 8bf9 a5 a5 a5 a5 }
            // n = 7, score = 100
            //   eb4f                 | jmp                 0x51
            //   8bf3                 | mov                 esi, ebx
            //   8bf9                 | mov                 edi, ecx
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]

        $sequence_7 = { 59 59 751c 8b45fc 8b4020 85c0 }
            // n = 6, score = 100
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   751c                 | jne                 0x1e
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   8b4020               | mov                 eax, dword ptr [eax + 0x20]
            //   85c0                 | test                eax, eax

        $sequence_8 = { 5e c20400 68???????? 6a20 33c0 }
            // n = 5, score = 100
            //   5e                   | pop                 esi
            //   c20400               | ret                 4
            //   68????????           |                     
            //   6a20                 | push                0x20
            //   33c0                 | xor                 eax, eax

        $sequence_9 = { 40 5e eb02 32c0 8b4d74 33cd }
            // n = 6, score = 100
            //   40                   | inc                 eax
            //   5e                   | pop                 esi
            //   eb02                 | jmp                 4
            //   32c0                 | xor                 al, al
            //   8b4d74               | mov                 ecx, dword ptr [ebp + 0x74]
            //   33cd                 | xor                 ecx, ebp

    condition:
        7 of them and filesize < 1392640
}