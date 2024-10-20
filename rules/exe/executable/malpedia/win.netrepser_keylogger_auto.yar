rule win_netrepser_keylogger_auto {

    meta:
        atk_type = "win.netrepser_keylogger."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.netrepser_keylogger."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netrepser_keylogger"
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
        $sequence_0 = { 8a55f3 80c201 8855f3 837df807 7517 0fbe45f3 c6840570ffffff3a }
            // n = 7, score = 200
            //   8a55f3               | mov                 dl, byte ptr [ebp - 0xd]
            //   80c201               | add                 dl, 1
            //   8855f3               | mov                 byte ptr [ebp - 0xd], dl
            //   837df807             | cmp                 dword ptr [ebp - 8], 7
            //   7517                 | jne                 0x19
            //   0fbe45f3             | movsx               eax, byte ptr [ebp - 0xd]
            //   c6840570ffffff3a     | mov                 byte ptr [ebp + eax - 0x90], 0x3a

        $sequence_1 = { 51 8b5508 52 ff15???????? eb71 8d45ec 50 }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   eb71                 | jmp                 0x73
            //   8d45ec               | lea                 eax, [ebp - 0x14]
            //   50                   | push                eax

        $sequence_2 = { 51 680104c378 e8???????? 83c40c 8d55e8 52 }
            // n = 6, score = 200
            //   51                   | push                ecx
            //   680104c378           | push                0x78c30401
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d55e8               | lea                 edx, [ebp - 0x18]
            //   52                   | push                edx

        $sequence_3 = { 8945f4 8b45f4 33d2 b900ca9a3b f7f1 8955f4 8b55f4 }
            // n = 7, score = 200
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   33d2                 | xor                 edx, edx
            //   b900ca9a3b           | mov                 ecx, 0x3b9aca00
            //   f7f1                 | div                 ecx
            //   8955f4               | mov                 dword ptr [ebp - 0xc], edx
            //   8b55f4               | mov                 edx, dword ptr [ebp - 0xc]

        $sequence_4 = { 33c9 894ddc 894de0 894de4 894de8 c745dc10000000 c745e001000000 }
            // n = 7, score = 200
            //   33c9                 | xor                 ecx, ecx
            //   894ddc               | mov                 dword ptr [ebp - 0x24], ecx
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx
            //   894de4               | mov                 dword ptr [ebp - 0x1c], ecx
            //   894de8               | mov                 dword ptr [ebp - 0x18], ecx
            //   c745dc10000000       | mov                 dword ptr [ebp - 0x24], 0x10
            //   c745e001000000       | mov                 dword ptr [ebp - 0x20], 1

        $sequence_5 = { 8b55f0 52 ff15???????? 8b45c0 8be5 }
            // n = 5, score = 200
            //   8b55f0               | mov                 edx, dword ptr [ebp - 0x10]
            //   52                   | push                edx
            //   ff15????????         |                     
            //   8b45c0               | mov                 eax, dword ptr [ebp - 0x40]
            //   8be5                 | mov                 esp, ebp

        $sequence_6 = { c645f274 c645f369 c645f466 c645f569 }
            // n = 4, score = 200
            //   c645f274             | mov                 byte ptr [ebp - 0xe], 0x74
            //   c645f369             | mov                 byte ptr [ebp - 0xd], 0x69
            //   c645f466             | mov                 byte ptr [ebp - 0xc], 0x66
            //   c645f569             | mov                 byte ptr [ebp - 0xb], 0x69

        $sequence_7 = { 7e0b 83bde4feffff08 7d02 ebcb 83bde4feffff1a 7e0b }
            // n = 6, score = 200
            //   7e0b                 | jle                 0xd
            //   83bde4feffff08       | cmp                 dword ptr [ebp - 0x11c], 8
            //   7d02                 | jge                 4
            //   ebcb                 | jmp                 0xffffffcd
            //   83bde4feffff1a       | cmp                 dword ptr [ebp - 0x11c], 0x1a
            //   7e0b                 | jle                 0xd

        $sequence_8 = { c744240c57726974 c74424106550726f c744241463657373 c74424184d656d6f c744241c72790000 ff15???????? a3???????? }
            // n = 7, score = 100
            //   c744240c57726974     | mov                 dword ptr [esp + 0xc], 0x74697257
            //   c74424106550726f     | mov                 dword ptr [esp + 0x10], 0x6f725065
            //   c744241463657373     | mov                 dword ptr [esp + 0x14], 0x73736563
            //   c74424184d656d6f     | mov                 dword ptr [esp + 0x18], 0x6f6d654d
            //   c744241c72790000     | mov                 dword ptr [esp + 0x1c], 0x7972
            //   ff15????????         |                     
            //   a3????????           |                     

        $sequence_9 = { 8b701c 8bcf e8???????? 8b4c240c }
            // n = 4, score = 100
            //   8b701c               | mov                 esi, dword ptr [eax + 0x1c]
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     
            //   8b4c240c             | mov                 ecx, dword ptr [esp + 0xc]

        $sequence_10 = { 51 c74424084f70656e c744240c50726f63 c744241065737300 ff15???????? a3???????? 8b542448 }
            // n = 7, score = 100
            //   51                   | push                ecx
            //   c74424084f70656e     | mov                 dword ptr [esp + 8], 0x6e65704f
            //   c744240c50726f63     | mov                 dword ptr [esp + 0xc], 0x636f7250
            //   c744241065737300     | mov                 dword ptr [esp + 0x10], 0x737365
            //   ff15????????         |                     
            //   a3????????           |                     
            //   8b542448             | mov                 edx, dword ptr [esp + 0x48]

        $sequence_11 = { 56 33ff 53 8906 894e08 }
            // n = 5, score = 100
            //   56                   | push                esi
            //   33ff                 | xor                 edi, edi
            //   53                   | push                ebx
            //   8906                 | mov                 dword ptr [esi], eax
            //   894e08               | mov                 dword ptr [esi + 8], ecx

        $sequence_12 = { 68???????? ff15???????? 8bf8 85ff 7472 }
            // n = 5, score = 100
            //   68????????           |                     
            //   ff15????????         |                     
            //   8bf8                 | mov                 edi, eax
            //   85ff                 | test                edi, edi
            //   7472                 | je                  0x74

        $sequence_13 = { 55 8b6c244c 85c0 7550 }
            // n = 4, score = 100
            //   55                   | push                ebp
            //   8b6c244c             | mov                 ebp, dword ptr [esp + 0x4c]
            //   85c0                 | test                eax, eax
            //   7550                 | jne                 0x52

        $sequence_14 = { f3a5 8b8c24b4000000 a4 8db329010000 56 }
            // n = 5, score = 100
            //   f3a5                 | rep movsd           dword ptr es:[edi], dword ptr [esi]
            //   8b8c24b4000000       | mov                 ecx, dword ptr [esp + 0xb4]
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   8db329010000         | lea                 esi, [ebx + 0x129]
            //   56                   | push                esi

        $sequence_15 = { b840000000 55 89442410 89442414 8d442410 50 8d4c2418 }
            // n = 7, score = 100
            //   b840000000           | mov                 eax, 0x40
            //   55                   | push                ebp
            //   89442410             | mov                 dword ptr [esp + 0x10], eax
            //   89442414             | mov                 dword ptr [esp + 0x14], eax
            //   8d442410             | lea                 eax, [esp + 0x10]
            //   50                   | push                eax
            //   8d4c2418             | lea                 ecx, [esp + 0x18]

    condition:
        7 of them and filesize < 303104
}