rule win_alreay_auto {

    meta:
        atk_type = "win.alreay."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.alreay."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alreay"
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
        $sequence_0 = { 8bca 83e103 03eb f3aa e9???????? 83fa07 7511 }
            // n = 7, score = 200
            //   8bca                 | mov                 ecx, edx
            //   83e103               | and                 ecx, 3
            //   03eb                 | add                 ebp, ebx
            //   f3aa                 | rep stosb           byte ptr es:[edi], al
            //   e9????????           |                     
            //   83fa07               | cmp                 edx, 7
            //   7511                 | jne                 0x13

        $sequence_1 = { 89b48484010000 8a442418 fec0 885c2420 8b5c2424 88442418 8b442420 }
            // n = 7, score = 200
            //   89b48484010000       | mov                 dword ptr [esp + eax*4 + 0x184], esi
            //   8a442418             | mov                 al, byte ptr [esp + 0x18]
            //   fec0                 | inc                 al
            //   885c2420             | mov                 byte ptr [esp + 0x20], bl
            //   8b5c2424             | mov                 ebx, dword ptr [esp + 0x24]
            //   88442418             | mov                 byte ptr [esp + 0x18], al
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]

        $sequence_2 = { 894c2404 7407 b802000000 eb1d 8b90e8010000 85d2 7411 }
            // n = 7, score = 200
            //   894c2404             | mov                 dword ptr [esp + 4], ecx
            //   7407                 | je                  9
            //   b802000000           | mov                 eax, 2
            //   eb1d                 | jmp                 0x1f
            //   8b90e8010000         | mov                 edx, dword ptr [eax + 0x1e8]
            //   85d2                 | test                edx, edx
            //   7411                 | je                  0x13

        $sequence_3 = { 89442428 85c0 0f850c010000 8b442420 3bc7 7608 8bd7 }
            // n = 7, score = 200
            //   89442428             | mov                 dword ptr [esp + 0x28], eax
            //   85c0                 | test                eax, eax
            //   0f850c010000         | jne                 0x112
            //   8b442420             | mov                 eax, dword ptr [esp + 0x20]
            //   3bc7                 | cmp                 eax, edi
            //   7608                 | jbe                 0xa
            //   8bd7                 | mov                 edx, edi

        $sequence_4 = { 8b8574010000 8bd1 23d0 83faff 0f848d000000 3bc3 7c55 }
            // n = 7, score = 200
            //   8b8574010000         | mov                 eax, dword ptr [ebp + 0x174]
            //   8bd1                 | mov                 edx, ecx
            //   23d0                 | and                 edx, eax
            //   83faff               | cmp                 edx, -1
            //   0f848d000000         | je                  0x93
            //   3bc3                 | cmp                 eax, ebx
            //   7c55                 | jl                  0x57

        $sequence_5 = { 8b15???????? 8b442414 8b742444 8b4c2448 42 40 83c604 }
            // n = 7, score = 200
            //   8b15????????         |                     
            //   8b442414             | mov                 eax, dword ptr [esp + 0x14]
            //   8b742444             | mov                 esi, dword ptr [esp + 0x44]
            //   8b4c2448             | mov                 ecx, dword ptr [esp + 0x48]
            //   42                   | inc                 edx
            //   40                   | inc                 eax
            //   83c604               | add                 esi, 4

        $sequence_6 = { 8a16 8bcf 84d2 8bc6 741d 8a10 80fa5c }
            // n = 7, score = 200
            //   8a16                 | mov                 dl, byte ptr [esi]
            //   8bcf                 | mov                 ecx, edi
            //   84d2                 | test                dl, dl
            //   8bc6                 | mov                 eax, esi
            //   741d                 | je                  0x1f
            //   8a10                 | mov                 dl, byte ptr [eax]
            //   80fa5c               | cmp                 dl, 0x5c

        $sequence_7 = { 8b8268020000 3bc1 0f852f040000 8b86b4040000 8bca 8b916c020000 3bd0 }
            // n = 7, score = 200
            //   8b8268020000         | mov                 eax, dword ptr [edx + 0x268]
            //   3bc1                 | cmp                 eax, ecx
            //   0f852f040000         | jne                 0x435
            //   8b86b4040000         | mov                 eax, dword ptr [esi + 0x4b4]
            //   8bca                 | mov                 ecx, edx
            //   8b916c020000         | mov                 edx, dword ptr [ecx + 0x26c]
            //   3bd0                 | cmp                 edx, eax

        $sequence_8 = { bb16000000 3bc3 bf15000000 0f85f5010000 8b7500 8b86cc000000 8bd0 }
            // n = 7, score = 200
            //   bb16000000           | mov                 ebx, 0x16
            //   3bc3                 | cmp                 eax, ebx
            //   bf15000000           | mov                 edi, 0x15
            //   0f85f5010000         | jne                 0x1fb
            //   8b7500               | mov                 esi, dword ptr [ebp]
            //   8b86cc000000         | mov                 eax, dword ptr [esi + 0xcc]
            //   8bd0                 | mov                 edx, eax

        $sequence_9 = { 8d7c2448 83c9ff 33c0 8b54241c f2ae f7d1 49 }
            // n = 7, score = 200
            //   8d7c2448             | lea                 edi, [esp + 0x48]
            //   83c9ff               | or                  ecx, 0xffffffff
            //   33c0                 | xor                 eax, eax
            //   8b54241c             | mov                 edx, dword ptr [esp + 0x1c]
            //   f2ae                 | repne scasb         al, byte ptr es:[edi]
            //   f7d1                 | not                 ecx
            //   49                   | dec                 ecx

    condition:
        7 of them and filesize < 1867776
}