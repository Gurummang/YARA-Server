rule win_rincux_auto {

    meta:
        atk_type = "win.rincux."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.rincux."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rincux"
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
        $sequence_0 = { 742d b9fa000000 33c0 8dbc24c0000000 8d9424c0000000 f3ab 8d8c24b0000000 }
            // n = 7, score = 200
            //   742d                 | je                  0x2f
            //   b9fa000000           | mov                 ecx, 0xfa
            //   33c0                 | xor                 eax, eax
            //   8dbc24c0000000       | lea                 edi, [esp + 0xc0]
            //   8d9424c0000000       | lea                 edx, [esp + 0xc0]
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   8d8c24b0000000       | lea                 ecx, [esp + 0xb0]

        $sequence_1 = { 8bcd 52 57 e8???????? 8b442410 8d4c2424 6a04 }
            // n = 7, score = 200
            //   8bcd                 | mov                 ecx, ebp
            //   52                   | push                edx
            //   57                   | push                edi
            //   e8????????           |                     
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   6a04                 | push                4

        $sequence_2 = { 7425 8b442410 8d4c2424 88442424 }
            // n = 4, score = 200
            //   7425                 | je                  0x27
            //   8b442410             | mov                 eax, dword ptr [esp + 0x10]
            //   8d4c2424             | lea                 ecx, [esp + 0x24]
            //   88442424             | mov                 byte ptr [esp + 0x24], al

        $sequence_3 = { c68424fd00000076 888c24fe000000 888424ff000000 c68424000100005c c684240101000052 c684240201000044 c684240301000050 }
            // n = 7, score = 200
            //   c68424fd00000076     | mov                 byte ptr [esp + 0xfd], 0x76
            //   888c24fe000000       | mov                 byte ptr [esp + 0xfe], cl
            //   888424ff000000       | mov                 byte ptr [esp + 0xff], al
            //   c68424000100005c     | mov                 byte ptr [esp + 0x100], 0x5c
            //   c684240101000052     | mov                 byte ptr [esp + 0x101], 0x52
            //   c684240201000044     | mov                 byte ptr [esp + 0x102], 0x44
            //   c684240301000050     | mov                 byte ptr [esp + 0x103], 0x50

        $sequence_4 = { c20800 33c0 8a4701 894614 8b4df4 64890d00000000 }
            // n = 6, score = 200
            //   c20800               | ret                 8
            //   33c0                 | xor                 eax, eax
            //   8a4701               | mov                 al, byte ptr [edi + 1]
            //   894614               | mov                 dword ptr [esi + 0x14], eax
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   64890d00000000       | mov                 dword ptr fs:[0], ecx

        $sequence_5 = { ff15???????? 83f8ff 7511 8b16 52 ff15???????? 5f }
            // n = 7, score = 200
            //   ff15????????         |                     
            //   83f8ff               | cmp                 eax, -1
            //   7511                 | jne                 0x13
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   5f                   | pop                 edi

        $sequence_6 = { 5e 83c42c c20400 8b542438 8d4c2408 51 52 }
            // n = 7, score = 200
            //   5e                   | pop                 esi
            //   83c42c               | add                 esp, 0x2c
            //   c20400               | ret                 4
            //   8b542438             | mov                 edx, dword ptr [esp + 0x38]
            //   8d4c2408             | lea                 ecx, [esp + 8]
            //   51                   | push                ecx
            //   52                   | push                edx

        $sequence_7 = { 84c0 74d8 5f 5e 5d 5b }
            // n = 6, score = 200
            //   84c0                 | test                al, al
            //   74d8                 | je                  0xffffffda
            //   5f                   | pop                 edi
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   5b                   | pop                 ebx

        $sequence_8 = { 53 57 8b7c242c 6683f90e 7502 }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   57                   | push                edi
            //   8b7c242c             | mov                 edi, dword ptr [esp + 0x2c]
            //   6683f90e             | cmp                 cx, 0xe
            //   7502                 | jne                 4

        $sequence_9 = { 50 68???????? e9???????? 40 c745fc00000000 50 e8???????? }
            // n = 7, score = 200
            //   50                   | push                eax
            //   68????????           |                     
            //   e9????????           |                     
            //   40                   | inc                 eax
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   50                   | push                eax
            //   e8????????           |                     

    condition:
        7 of them and filesize < 392192
}