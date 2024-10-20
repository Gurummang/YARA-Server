rule win_rofin_auto {

    meta:
        atk_type = "win.rofin."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rofin."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rofin"
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
        $sequence_0 = { 014df0 3b06 72b5 eb1a 8b45fc 69c01c010000 03c6 }
            // n = 7, score = 100
            //   014df0               | add                 dword ptr [ebp - 0x10], ecx
            //   3b06                 | cmp                 eax, dword ptr [esi]
            //   72b5                 | jb                  0xffffffb7
            //   eb1a                 | jmp                 0x1c
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   69c01c010000         | imul                eax, eax, 0x11c
            //   03c6                 | add                 eax, esi

        $sequence_1 = { 84c0 c706???????? 7417 8b4604 85c0 7410 }
            // n = 6, score = 100
            //   84c0                 | test                al, al
            //   c706????????         |                     
            //   7417                 | je                  0x19
            //   8b4604               | mov                 eax, dword ptr [esi + 4]
            //   85c0                 | test                eax, eax
            //   7410                 | je                  0x12

        $sequence_2 = { 8d442434 53 50 33d2 668b95d0030000 56 8d4c242c }
            // n = 7, score = 100
            //   8d442434             | lea                 eax, [esp + 0x34]
            //   53                   | push                ebx
            //   50                   | push                eax
            //   33d2                 | xor                 edx, edx
            //   668b95d0030000       | mov                 dx, word ptr [ebp + 0x3d0]
            //   56                   | push                esi
            //   8d4c242c             | lea                 ecx, [esp + 0x2c]

        $sequence_3 = { c644244163 88542442 c644244528 885c2446 c64424473e c644244800 }
            // n = 6, score = 100
            //   c644244163           | mov                 byte ptr [esp + 0x41], 0x63
            //   88542442             | mov                 byte ptr [esp + 0x42], dl
            //   c644244528           | mov                 byte ptr [esp + 0x45], 0x28
            //   885c2446             | mov                 byte ptr [esp + 0x46], bl
            //   c64424473e           | mov                 byte ptr [esp + 0x47], 0x3e
            //   c644244800           | mov                 byte ptr [esp + 0x48], 0

        $sequence_4 = { 8b44240c 8b542404 83ec10 8d4c2400 53 50 }
            // n = 6, score = 100
            //   8b44240c             | mov                 eax, dword ptr [esp + 0xc]
            //   8b542404             | mov                 edx, dword ptr [esp + 4]
            //   83ec10               | sub                 esp, 0x10
            //   8d4c2400             | lea                 ecx, [esp]
            //   53                   | push                ebx
            //   50                   | push                eax

        $sequence_5 = { 83c408 3bf3 7420 8b4c2420 56 8b513c 52 }
            // n = 7, score = 100
            //   83c408               | add                 esp, 8
            //   3bf3                 | cmp                 esi, ebx
            //   7420                 | je                  0x22
            //   8b4c2420             | mov                 ecx, dword ptr [esp + 0x20]
            //   56                   | push                esi
            //   8b513c               | mov                 edx, dword ptr [ecx + 0x3c]
            //   52                   | push                edx

        $sequence_6 = { 72b5 eb1a 8b45fc 69c01c010000 03c6 81781000d00000 7506 }
            // n = 7, score = 100
            //   72b5                 | jb                  0xffffffb7
            //   eb1a                 | jmp                 0x1c
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   69c01c010000         | imul                eax, eax, 0x11c
            //   03c6                 | add                 eax, esi
            //   81781000d00000       | cmp                 dword ptr [eax + 0x10], 0xd000
            //   7506                 | jne                 8

        $sequence_7 = { f3a4 8d4c246a 6800040000 51 6a00 ff15???????? }
            // n = 6, score = 100
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d4c246a             | lea                 ecx, [esp + 0x6a]
            //   6800040000           | push                0x400
            //   51                   | push                ecx
            //   6a00                 | push                0
            //   ff15????????         |                     

        $sequence_8 = { e8???????? eb73 bf???????? 83c9ff 33c0 f2ae f7d1 }
            // n = 7, score = 100
            //   e8????????           |                     
            //   eb73                 | jmp                 0x75
            //   bf????????           |                     
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx

        $sequence_9 = { 8b45fc 83481c10 8b45fc 89585c 8d45f4 }
            // n = 5, score = 100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   83481c10             | or                  dword ptr [eax + 0x1c], 0x10
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   89585c               | mov                 dword ptr [eax + 0x5c], ebx
            //   8d45f4               | lea                 eax, [ebp - 0xc]

    condition:
        7 of them and filesize < 409600
}