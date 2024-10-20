rule win_kronos_auto {

    meta:
        atk_type = "win.kronos."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.kronos."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kronos"
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
        $sequence_0 = { 8d542450 52 03c6 50 57 ffd3 85c0 }
            // n = 7, score = 2800
            //   8d542450             | lea                 edx, [esp + 0x50]
            //   52                   | push                edx
            //   03c6                 | add                 eax, esi
            //   50                   | push                eax
            //   57                   | push                edi
            //   ffd3                 | call                ebx
            //   85c0                 | test                eax, eax

        $sequence_1 = { 813e50450000 7549 57 56 ff75fc e8???????? 8b450c }
            // n = 7, score = 2800
            //   813e50450000         | cmp                 dword ptr [esi], 0x4550
            //   7549                 | jne                 0x4b
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   e8????????           |                     
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]

        $sequence_2 = { e8???????? 33db 6a40 8d4628 53 50 }
            // n = 6, score = 2800
            //   e8????????           |                     
            //   33db                 | xor                 ebx, ebx
            //   6a40                 | push                0x40
            //   8d4628               | lea                 eax, [esi + 0x28]
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_3 = { e8???????? 85db 0f854fffffff eb1c 8d4dd0 be02000000 e8???????? }
            // n = 7, score = 2800
            //   e8????????           |                     
            //   85db                 | test                ebx, ebx
            //   0f854fffffff         | jne                 0xffffff55
            //   eb1c                 | jmp                 0x1e
            //   8d4dd0               | lea                 ecx, [ebp - 0x30]
            //   be02000000           | mov                 esi, 2
            //   e8????????           |                     

        $sequence_4 = { 897804 8930 ff461c 6a00 }
            // n = 4, score = 2800
            //   897804               | mov                 dword ptr [eax + 4], edi
            //   8930                 | mov                 dword ptr [eax], esi
            //   ff461c               | inc                 dword ptr [esi + 0x1c]
            //   6a00                 | push                0

        $sequence_5 = { 803d????????01 56 750f 33f6 8d4df0 e8???????? 8bc6 }
            // n = 7, score = 2800
            //   803d????????01       |                     
            //   56                   | push                esi
            //   750f                 | jne                 0x11
            //   33f6                 | xor                 esi, esi
            //   8d4df0               | lea                 ecx, [ebp - 0x10]
            //   e8????????           |                     
            //   8bc6                 | mov                 eax, esi

        $sequence_6 = { eb1d 8b0f e8???????? 8b0f 8b30 6a04 e8???????? }
            // n = 7, score = 2800
            //   eb1d                 | jmp                 0x1f
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   e8????????           |                     
            //   8b0f                 | mov                 ecx, dword ptr [edi]
            //   8b30                 | mov                 esi, dword ptr [eax]
            //   6a04                 | push                4
            //   e8????????           |                     

        $sequence_7 = { 0355dc 8b45e8 2b45ec 03ca 3b450c 7356 29450c }
            // n = 7, score = 2800
            //   0355dc               | add                 edx, dword ptr [ebp - 0x24]
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   2b45ec               | sub                 eax, dword ptr [ebp - 0x14]
            //   03ca                 | add                 ecx, edx
            //   3b450c               | cmp                 eax, dword ptr [ebp + 0xc]
            //   7356                 | jae                 0x58
            //   29450c               | sub                 dword ptr [ebp + 0xc], eax

        $sequence_8 = { c3 55 8bec 83ec5c 56 8d45a4 50 }
            // n = 7, score = 2800
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   83ec5c               | sub                 esp, 0x5c
            //   56                   | push                esi
            //   8d45a4               | lea                 eax, [ebp - 0x5c]
            //   50                   | push                eax

        $sequence_9 = { 3b7104 7505 8b06 894104 3b7108 7506 8b5604 }
            // n = 7, score = 2800
            //   3b7104               | cmp                 esi, dword ptr [ecx + 4]
            //   7505                 | jne                 7
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   894104               | mov                 dword ptr [ecx + 4], eax
            //   3b7108               | cmp                 esi, dword ptr [ecx + 8]
            //   7506                 | jne                 8
            //   8b5604               | mov                 edx, dword ptr [esi + 4]

    condition:
        7 of them and filesize < 1302528
}