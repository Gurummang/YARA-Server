rule win_snowflake_stealer_auto {

    meta:
        atk_type = "win.snowflake_stealer."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.snowflake_stealer."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snowflake_stealer"
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
        $sequence_0 = { f20f114740 0fb64111 894738 89473c ff5308 8b542418 59 }
            // n = 7, score = 100
            //   f20f114740           | movsd               qword ptr [edi + 0x40], xmm0
            //   0fb64111             | movzx               eax, byte ptr [ecx + 0x11]
            //   894738               | mov                 dword ptr [edi + 0x38], eax
            //   89473c               | mov                 dword ptr [edi + 0x3c], eax
            //   ff5308               | call                dword ptr [ebx + 8]
            //   8b542418             | mov                 edx, dword ptr [esp + 0x18]
            //   59                   | pop                 ecx

        $sequence_1 = { f30fe6c0 660f2fc8 7623 84d2 750a f30f1048fc 0f5ac9 }
            // n = 7, score = 100
            //   f30fe6c0             | cvtdq2pd            xmm0, xmm0
            //   660f2fc8             | comisd              xmm1, xmm0
            //   7623                 | jbe                 0x25
            //   84d2                 | test                dl, dl
            //   750a                 | jne                 0xc
            //   f30f1048fc           | movss               xmm1, dword ptr [eax - 4]
            //   0f5ac9               | cvtps2pd            xmm1, xmm1

        $sequence_2 = { f20f1000 f20f1106 8b4008 c7030a000000 894608 53 56 }
            // n = 7, score = 100
            //   f20f1000             | movsd               xmm0, qword ptr [eax]
            //   f20f1106             | movsd               qword ptr [esi], xmm0
            //   8b4008               | mov                 eax, dword ptr [eax + 8]
            //   c7030a000000         | mov                 dword ptr [ebx], 0xa
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   53                   | push                ebx
            //   56                   | push                esi

        $sequence_3 = { eb54 8b54241c 8d4c2474 e8???????? 8b44247c 8b8c2480000000 31f6 }
            // n = 7, score = 100
            //   eb54                 | jmp                 0x56
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]
            //   8d4c2474             | lea                 ecx, [esp + 0x74]
            //   e8????????           |                     
            //   8b44247c             | mov                 eax, dword ptr [esp + 0x7c]
            //   8b8c2480000000       | mov                 ecx, dword ptr [esp + 0x80]
            //   31f6                 | xor                 esi, esi

        $sequence_4 = { ff753c ff74241c e8???????? 59 59 83650800 83650c00 }
            // n = 7, score = 100
            //   ff753c               | push                dword ptr [ebp + 0x3c]
            //   ff74241c             | push                dword ptr [esp + 0x1c]
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   83650800             | and                 dword ptr [ebp + 8], 0
            //   83650c00             | and                 dword ptr [ebp + 0xc], 0

        $sequence_5 = { ff7010 ff700c ff7110 ff710c ff7608 ff560c 83c414 }
            // n = 7, score = 100
            //   ff7010               | push                dword ptr [eax + 0x10]
            //   ff700c               | push                dword ptr [eax + 0xc]
            //   ff7110               | push                dword ptr [ecx + 0x10]
            //   ff710c               | push                dword ptr [ecx + 0xc]
            //   ff7608               | push                dword ptr [esi + 8]
            //   ff560c               | call                dword ptr [esi + 0xc]
            //   83c414               | add                 esp, 0x14

        $sequence_6 = { ff750c e8???????? 83c410 5f 8bc6 5e 5b }
            // n = 7, score = 100
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   e8????????           |                     
            //   83c410               | add                 esp, 0x10
            //   5f                   | pop                 edi
            //   8bc6                 | mov                 eax, esi
            //   5e                   | pop                 esi
            //   5b                   | pop                 ebx

        $sequence_7 = { ff742428 e8???????? 50 53 56 e8???????? 8bd8 }
            // n = 7, score = 100
            //   ff742428             | push                dword ptr [esp + 0x28]
            //   e8????????           |                     
            //   50                   | push                eax
            //   53                   | push                ebx
            //   56                   | push                esi
            //   e8????????           |                     
            //   8bd8                 | mov                 ebx, eax

        $sequence_8 = { c745f001000000 894ddc 51 8945e0 ff500c 83c404 8b45e0 }
            // n = 7, score = 100
            //   c745f001000000       | mov                 dword ptr [ebp - 0x10], 1
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx
            //   51                   | push                ecx
            //   8945e0               | mov                 dword ptr [ebp - 0x20], eax
            //   ff500c               | call                dword ptr [eax + 0xc]
            //   83c404               | add                 esp, 4
            //   8b45e0               | mov                 eax, dword ptr [ebp - 0x20]

        $sequence_9 = { ff7310 e8???????? 8bf0 83c40c 85f6 756f 55 }
            // n = 7, score = 100
            //   ff7310               | push                dword ptr [ebx + 0x10]
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax
            //   83c40c               | add                 esp, 0xc
            //   85f6                 | test                esi, esi
            //   756f                 | jne                 0x71
            //   55                   | push                ebp

    condition:
        7 of them and filesize < 6196224
}