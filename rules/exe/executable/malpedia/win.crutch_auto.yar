rule win_crutch_auto {

    meta:
        atk_type = "win.crutch."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.crutch."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crutch"
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
        $sequence_0 = { 7536 8b8740030000 f7404000c00000 51 740f 8b4e6c 51 }
            // n = 7, score = 100
            //   7536                 | jne                 0x38
            //   8b8740030000         | mov                 eax, dword ptr [edi + 0x340]
            //   f7404000c00000       | test                dword ptr [eax + 0x40], 0xc000
            //   51                   | push                ecx
            //   740f                 | je                  0x11
            //   8b4e6c               | mov                 ecx, dword ptr [esi + 0x6c]
            //   51                   | push                ecx

        $sequence_1 = { 8b442430 85c0 742b 8b942488000000 8b8c2484000000 52 8b54243c }
            // n = 7, score = 100
            //   8b442430             | mov                 eax, dword ptr [esp + 0x30]
            //   85c0                 | test                eax, eax
            //   742b                 | je                  0x2d
            //   8b942488000000       | mov                 edx, dword ptr [esp + 0x88]
            //   8b8c2484000000       | mov                 ecx, dword ptr [esp + 0x84]
            //   52                   | push                edx
            //   8b54243c             | mov                 edx, dword ptr [esp + 0x3c]

        $sequence_2 = { 8b01 50 ff30 51 ff32 8bcb e8???????? }
            // n = 7, score = 100
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   50                   | push                eax
            //   ff30                 | push                dword ptr [eax]
            //   51                   | push                ecx
            //   ff32                 | push                dword ptr [edx]
            //   8bcb                 | mov                 ecx, ebx
            //   e8????????           |                     

        $sequence_3 = { 50 8d4ddc e8???????? eb3a 8dbd1cffffff 8d3cd7 8d8514ffffff }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d4ddc               | lea                 ecx, [ebp - 0x24]
            //   e8????????           |                     
            //   eb3a                 | jmp                 0x3c
            //   8dbd1cffffff         | lea                 edi, [ebp - 0xe4]
            //   8d3cd7               | lea                 edi, [edi + edx*8]
            //   8d8514ffffff         | lea                 eax, [ebp - 0xec]

        $sequence_4 = { 8b6c2408 7426 8b03 50 ff15???????? 8b8efc040000 51 }
            // n = 7, score = 100
            //   8b6c2408             | mov                 ebp, dword ptr [esp + 8]
            //   7426                 | je                  0x28
            //   8b03                 | mov                 eax, dword ptr [ebx]
            //   50                   | push                eax
            //   ff15????????         |                     
            //   8b8efc040000         | mov                 ecx, dword ptr [esi + 0x4fc]
            //   51                   | push                ecx

        $sequence_5 = { 0f84f9000000 b9???????? 8bc6 8d642400 8a10 3a11 751a }
            // n = 7, score = 100
            //   0f84f9000000         | je                  0xff
            //   b9????????           |                     
            //   8bc6                 | mov                 eax, esi
            //   8d642400             | lea                 esp, [esp]
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   3a11                 | cmp                 dl, byte ptr [ecx]
            //   751a                 | jne                 0x1c

        $sequence_6 = { 81c2cc000000 89542408 8b54240c 89542404 e9???????? 81f9244e0000 }
            // n = 6, score = 100
            //   81c2cc000000         | add                 edx, 0xcc
            //   89542408             | mov                 dword ptr [esp + 8], edx
            //   8b54240c             | mov                 edx, dword ptr [esp + 0xc]
            //   89542404             | mov                 dword ptr [esp + 4], edx
            //   e9????????           |                     
            //   81f9244e0000         | cmp                 ecx, 0x4e24

        $sequence_7 = { 7506 8b7c2428 eb4a 41 51 ff15???????? 8bf8 }
            // n = 7, score = 100
            //   7506                 | jne                 8
            //   8b7c2428             | mov                 edi, dword ptr [esp + 0x28]
            //   eb4a                 | jmp                 0x4c
            //   41                   | inc                 ecx
            //   51                   | push                ecx
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_8 = { b823000000 5e c3 8d471f c1e004 8bcf c1e104 }
            // n = 7, score = 100
            //   b823000000           | mov                 eax, 0x23
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8d471f               | lea                 eax, [edi + 0x1f]
            //   c1e004               | shl                 eax, 4
            //   8bcf                 | mov                 ecx, edi
            //   c1e104               | shl                 ecx, 4

        $sequence_9 = { 8bf1 8a02 8806 8d4e18 8b4208 894608 8b420c }
            // n = 7, score = 100
            //   8bf1                 | mov                 esi, ecx
            //   8a02                 | mov                 al, byte ptr [edx]
            //   8806                 | mov                 byte ptr [esi], al
            //   8d4e18               | lea                 ecx, [esi + 0x18]
            //   8b4208               | mov                 eax, dword ptr [edx + 8]
            //   894608               | mov                 dword ptr [esi + 8], eax
            //   8b420c               | mov                 eax, dword ptr [edx + 0xc]

    condition:
        7 of them and filesize < 1067008
}