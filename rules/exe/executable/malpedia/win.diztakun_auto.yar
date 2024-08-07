rule win_diztakun_auto {

    meta:
        atk_type = "win.diztakun."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.diztakun."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.diztakun"
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
        $sequence_0 = { 4a 85d2 0f8fb3010000 8b08 8b11 50 }
            // n = 6, score = 100
            //   4a                   | dec                 edx
            //   85d2                 | test                edx, edx
            //   0f8fb3010000         | jg                  0x1b9
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   50                   | push                eax

        $sequence_1 = { 51 ff15???????? 8d742408 e8???????? 5f }
            // n = 5, score = 100
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8d742408             | lea                 esi, [esp + 8]
            //   e8????????           |                     
            //   5f                   | pop                 edi

        $sequence_2 = { 8b08 8b11 50 8b4204 ffd0 c68424d807000019 8b442430 }
            // n = 7, score = 100
            //   8b08                 | mov                 ecx, dword ptr [eax]
            //   8b11                 | mov                 edx, dword ptr [ecx]
            //   50                   | push                eax
            //   8b4204               | mov                 eax, dword ptr [edx + 4]
            //   ffd0                 | call                eax
            //   c68424d807000019     | mov                 byte ptr [esp + 0x7d8], 0x19
            //   8b442430             | mov                 eax, dword ptr [esp + 0x30]

        $sequence_3 = { 83e01f c1f905 8b0c8d60d74400 c1e006 03c1 f6400401 7524 }
            // n = 7, score = 100
            //   83e01f               | and                 eax, 0x1f
            //   c1f905               | sar                 ecx, 5
            //   8b0c8d60d74400       | mov                 ecx, dword ptr [ecx*4 + 0x44d760]
            //   c1e006               | shl                 eax, 6
            //   03c1                 | add                 eax, ecx
            //   f6400401             | test                byte ptr [eax + 4], 1
            //   7524                 | jne                 0x26

        $sequence_4 = { 8945f4 8b4514 40 c745ec3f344200 894df8 }
            // n = 5, score = 100
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   40                   | inc                 eax
            //   c745ec3f344200       | mov                 dword ptr [ebp - 0x14], 0x42343f
            //   894df8               | mov                 dword ptr [ebp - 8], ecx

        $sequence_5 = { 50 889c24e4070000 e8???????? 83c40c c68424d807000011 }
            // n = 5, score = 100
            //   50                   | push                eax
            //   889c24e4070000       | mov                 byte ptr [esp + 0x7e4], bl
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   c68424d807000011     | mov                 byte ptr [esp + 0x7d8], 0x11

        $sequence_6 = { 8b4c240c 8b5720 8d442408 50 51 }
            // n = 5, score = 100
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]
            //   8b5720               | mov                 edx, dword ptr [edi + 0x20]
            //   8d442408             | lea                 eax, [esp + 8]
            //   50                   | push                eax
            //   51                   | push                ecx

        $sequence_7 = { 85d2 740b 8b450c 8b80a4914400 eb09 8b450c 8b8070914400 }
            // n = 7, score = 100
            //   85d2                 | test                edx, edx
            //   740b                 | je                  0xd
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b80a4914400         | mov                 eax, dword ptr [eax + 0x4491a4]
            //   eb09                 | jmp                 0xb
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8b8070914400         | mov                 eax, dword ptr [eax + 0x449170]

        $sequence_8 = { e8???????? 59 59 85c0 0f84d9000000 68???????? 53 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   85c0                 | test                eax, eax
            //   0f84d9000000         | je                  0xdf
            //   68????????           |                     
            //   53                   | push                ebx

        $sequence_9 = { e8???????? 83bfac00000000 755e 8d4c2474 51 8d54241c 52 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   83bfac00000000       | cmp                 dword ptr [edi + 0xac], 0
            //   755e                 | jne                 0x60
            //   8d4c2474             | lea                 ecx, [esp + 0x74]
            //   51                   | push                ecx
            //   8d54241c             | lea                 edx, [esp + 0x1c]
            //   52                   | push                edx

    condition:
        7 of them and filesize < 688128
}