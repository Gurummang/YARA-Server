rule win_rockloader_auto {

    meta:
        atk_type = "win.rockloader."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rockloader."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rockloader"
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
        $sequence_0 = { e8???????? dc1d???????? dfe0 f6c441 740f }
            // n = 5, score = 300
            //   e8????????           |                     
            //   dc1d????????         |                     
            //   dfe0                 | fnstsw              ax
            //   f6c441               | test                ah, 0x41
            //   740f                 | je                  0x11

        $sequence_1 = { e8???????? 85c0 74b4 c6002c 40 837d0c00 7404 }
            // n = 7, score = 300
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   74b4                 | je                  0xffffffb6
            //   c6002c               | mov                 byte ptr [eax], 0x2c
            //   40                   | inc                 eax
            //   837d0c00             | cmp                 dword ptr [ebp + 0xc], 0
            //   7404                 | je                  6

        $sequence_2 = { 8a06 3c22 750c ff7508 8bc6 e8???????? }
            // n = 6, score = 300
            //   8a06                 | mov                 al, byte ptr [esi]
            //   3c22                 | cmp                 al, 0x22
            //   750c                 | jne                 0xe
            //   ff7508               | push                dword ptr [ebp + 8]
            //   8bc6                 | mov                 eax, esi
            //   e8????????           |                     

        $sequence_3 = { 8b45f4 8945e8 8d45f8 50 8d45e4 }
            // n = 5, score = 300
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8945e8               | mov                 dword ptr [ebp - 0x18], eax
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   8d45e4               | lea                 eax, [ebp - 0x1c]

        $sequence_4 = { eb05 68???????? e8???????? 8bf8 8bc7 }
            // n = 5, score = 300
            //   eb05                 | jmp                 7
            //   68????????           |                     
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   8bc7                 | mov                 eax, edi

        $sequence_5 = { e8???????? 33f6 53 8975f8 }
            // n = 4, score = 300
            //   e8????????           |                     
            //   33f6                 | xor                 esi, esi
            //   53                   | push                ebx
            //   8975f8               | mov                 dword ptr [ebp - 8], esi

        $sequence_6 = { 3975f4 7e55 53 8b45f8 }
            // n = 4, score = 300
            //   3975f4               | cmp                 dword ptr [ebp - 0xc], esi
            //   7e55                 | jle                 0x57
            //   53                   | push                ebx
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]

        $sequence_7 = { ff4608 8b7f08 85ff 7452 8b4508 }
            // n = 5, score = 300
            //   ff4608               | inc                 dword ptr [esi + 8]
            //   8b7f08               | mov                 edi, dword ptr [edi + 8]
            //   85ff                 | test                edi, edi
            //   7452                 | je                  0x54
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]

        $sequence_8 = { d9ee 53 56 dd55ec d9e8 33f6 }
            // n = 6, score = 300
            //   d9ee                 | fldz                
            //   53                   | push                ebx
            //   56                   | push                esi
            //   dd55ec               | fst                 qword ptr [ebp - 0x14]
            //   d9e8                 | fld1                
            //   33f6                 | xor                 esi, esi

        $sequence_9 = { 8975f8 db45f8 8365f800 dec1 dd5ddc 9b }
            // n = 6, score = 300
            //   8975f8               | mov                 dword ptr [ebp - 8], esi
            //   db45f8               | fild                dword ptr [ebp - 8]
            //   8365f800             | and                 dword ptr [ebp - 8], 0
            //   dec1                 | faddp               st(1)
            //   dd5ddc               | fstp                qword ptr [ebp - 0x24]
            //   9b                   | wait                

    condition:
        7 of them and filesize < 98304
}