rule win_freenki_auto {

    meta:
        atk_type = "win.freenki."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.freenki."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.freenki"
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
        $sequence_0 = { 83e03f 6bc830 8b049578394200 c644082801 897de4 c745fcfeffffff }
            // n = 6, score = 200
            //   83e03f               | and                 eax, 0x3f
            //   6bc830               | imul                ecx, eax, 0x30
            //   8b049578394200       | mov                 eax, dword ptr [edx*4 + 0x423978]
            //   c644082801           | mov                 byte ptr [eax + ecx + 0x28], 1
            //   897de4               | mov                 dword ptr [ebp - 0x1c], edi
            //   c745fcfeffffff       | mov                 dword ptr [ebp - 4], 0xfffffffe

        $sequence_1 = { 57 e8???????? 83c404 ff75f8 e8???????? 8bf8 }
            // n = 6, score = 200
            //   57                   | push                edi
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   ff75f8               | push                dword ptr [ebp - 8]
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax

        $sequence_2 = { f7d9 0bc8 51 53 e8???????? ffb504e7ffff 8bd8 }
            // n = 7, score = 200
            //   f7d9                 | neg                 ecx
            //   0bc8                 | or                  ecx, eax
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   e8????????           |                     
            //   ffb504e7ffff         | push                dword ptr [ebp - 0x18fc]
            //   8bd8                 | mov                 ebx, eax

        $sequence_3 = { 68???????? 50 ff5110 8b55b8 8b4dcc 2bd1 0f1f440000 }
            // n = 7, score = 200
            //   68????????           |                     
            //   50                   | push                eax
            //   ff5110               | call                dword ptr [ecx + 0x10]
            //   8b55b8               | mov                 edx, dword ptr [ebp - 0x48]
            //   8b4dcc               | mov                 ecx, dword ptr [ebp - 0x34]
            //   2bd1                 | sub                 edx, ecx
            //   0f1f440000           | nop                 dword ptr [eax + eax]

        $sequence_4 = { 6bd830 8b04bd78394200 f644032801 7444 837c0318ff 743d e8???????? }
            // n = 7, score = 200
            //   6bd830               | imul                ebx, eax, 0x30
            //   8b04bd78394200       | mov                 eax, dword ptr [edi*4 + 0x423978]
            //   f644032801           | test                byte ptr [ebx + eax + 0x28], 1
            //   7444                 | je                  0x46
            //   837c0318ff           | cmp                 dword ptr [ebx + eax + 0x18], -1
            //   743d                 | je                  0x3f
            //   e8????????           |                     

        $sequence_5 = { e8???????? 8b3d???????? 33db 0f1f8000000000 8d853cd4ffff 50 }
            // n = 6, score = 200
            //   e8????????           |                     
            //   8b3d????????         |                     
            //   33db                 | xor                 ebx, ebx
            //   0f1f8000000000       | nop                 dword ptr [eax]
            //   8d853cd4ffff         | lea                 eax, [ebp - 0x2bc4]
            //   50                   | push                eax

        $sequence_6 = { 64a300000000 8bf1 89b5e4edffff 33c0 c785c0edffff00000000 }
            // n = 5, score = 200
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8bf1                 | mov                 esi, ecx
            //   89b5e4edffff         | mov                 dword ptr [ebp - 0x121c], esi
            //   33c0                 | xor                 eax, eax
            //   c785c0edffff00000000     | mov    dword ptr [ebp - 0x1240], 0

        $sequence_7 = { 6bce4c 53 0f100419 0f1100 e8???????? 8b4dfc 83c404 }
            // n = 7, score = 200
            //   6bce4c               | imul                ecx, esi, 0x4c
            //   53                   | push                ebx
            //   0f100419             | movups              xmm0, xmmword ptr [ecx + ebx]
            //   0f1100               | movups              xmmword ptr [eax], xmm0
            //   e8????????           |                     
            //   8b4dfc               | mov                 ecx, dword ptr [ebp - 4]
            //   83c404               | add                 esp, 4

        $sequence_8 = { 68???????? ffb5e0f9ffff ff15???????? f7d8 5e }
            // n = 5, score = 200
            //   68????????           |                     
            //   ffb5e0f9ffff         | push                dword ptr [ebp - 0x620]
            //   ff15????????         |                     
            //   f7d8                 | neg                 eax
            //   5e                   | pop                 esi

        $sequence_9 = { dd00 ebc6 c745e0b8de4100 e9???????? c745e0c0de4100 e9???????? }
            // n = 6, score = 200
            //   dd00                 | fld                 qword ptr [eax]
            //   ebc6                 | jmp                 0xffffffc8
            //   c745e0b8de4100       | mov                 dword ptr [ebp - 0x20], 0x41deb8
            //   e9????????           |                     
            //   c745e0c0de4100       | mov                 dword ptr [ebp - 0x20], 0x41dec0
            //   e9????????           |                     

    condition:
        7 of them and filesize < 327680
}