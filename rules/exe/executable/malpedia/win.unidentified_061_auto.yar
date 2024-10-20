rule win_unidentified_061_auto {

    meta:
        atk_type = "win.unidentified_061."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-07-11"
        version = "1"
        description = "Detects win.unidentified_061."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_061"
        malpedia_rule_date = "20230705"
        malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
        malpedia_version = "20230715"
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
        $sequence_0 = { 8d85d4fdffff 50 e8???????? c9 }
            // n = 4, score = 200
            //   8d85d4fdffff         | lea                 eax, [ebp - 0x22c]
            //   50                   | push                eax
            //   e8????????           |                     
            //   c9                   | leave               

        $sequence_1 = { 89b5f0fdffff 899decfdffff 89b5f4feffff 899df0feffff ff15???????? 8945fc }
            // n = 6, score = 200
            //   89b5f0fdffff         | mov                 dword ptr [ebp - 0x210], esi
            //   899decfdffff         | mov                 dword ptr [ebp - 0x214], ebx
            //   89b5f4feffff         | mov                 dword ptr [ebp - 0x10c], esi
            //   899df0feffff         | mov                 dword ptr [ebp - 0x110], ebx
            //   ff15????????         |                     
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_2 = { 51 8365fc00 8d45fc 50 68???????? 6801000080 ff15???????? }
            // n = 7, score = 200
            //   51                   | push                ecx
            //   8365fc00             | and                 dword ptr [ebp - 4], 0
            //   8d45fc               | lea                 eax, [ebp - 4]
            //   50                   | push                eax
            //   68????????           |                     
            //   6801000080           | push                0x80000001
            //   ff15????????         |                     

        $sequence_3 = { 8945f0 0fb705???????? 50 ff15???????? 668945ee }
            // n = 5, score = 200
            //   8945f0               | mov                 dword ptr [ebp - 0x10], eax
            //   0fb705????????       |                     
            //   50                   | push                eax
            //   ff15????????         |                     
            //   668945ee             | mov                 word ptr [ebp - 0x12], ax

        $sequence_4 = { 68???????? 56 ff15???????? 83c41c 8d4601 5e eb09 }
            // n = 7, score = 200
            //   68????????           |                     
            //   56                   | push                esi
            //   ff15????????         |                     
            //   83c41c               | add                 esp, 0x1c
            //   8d4601               | lea                 eax, [esi + 1]
            //   5e                   | pop                 esi
            //   eb09                 | jmp                 0xb

        $sequence_5 = { 7417 03f3 3bf7 7ccb eb2f 7d29 }
            // n = 6, score = 200
            //   7417                 | je                  0x19
            //   03f3                 | add                 esi, ebx
            //   3bf7                 | cmp                 esi, edi
            //   7ccb                 | jl                  0xffffffcd
            //   eb2f                 | jmp                 0x31
            //   7d29                 | jge                 0x2b

        $sequence_6 = { 83cfff c6457300 3b7566 7cb5 3b7566 }
            // n = 5, score = 200
            //   83cfff               | or                  edi, 0xffffffff
            //   c6457300             | mov                 byte ptr [ebp + 0x73], 0
            //   3b7566               | cmp                 esi, dword ptr [ebp + 0x66]
            //   7cb5                 | jl                  0xffffffb7
            //   3b7566               | cmp                 esi, dword ptr [ebp + 0x66]

        $sequence_7 = { 53 57 6a04 33ff 33db }
            // n = 5, score = 200
            //   53                   | push                ebx
            //   57                   | push                edi
            //   6a04                 | push                4
            //   33ff                 | xor                 edi, edi
            //   33db                 | xor                 ebx, ebx

        $sequence_8 = { 5b c9 c20800 81ec00040000 68???????? 68???????? ff15???????? }
            // n = 7, score = 200
            //   5b                   | pop                 ebx
            //   c9                   | leave               
            //   c20800               | ret                 8
            //   81ec00040000         | sub                 esp, 0x400
            //   68????????           |                     
            //   68????????           |                     
            //   ff15????????         |                     

        $sequence_9 = { eb04 c645fb3d 6a05 8d45f8 50 ff750c c645fc00 }
            // n = 7, score = 200
            //   eb04                 | jmp                 6
            //   c645fb3d             | mov                 byte ptr [ebp - 5], 0x3d
            //   6a05                 | push                5
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax
            //   ff750c               | push                dword ptr [ebp + 0xc]
            //   c645fc00             | mov                 byte ptr [ebp - 4], 0

    condition:
        7 of them and filesize < 360448
}