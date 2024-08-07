rule win_cloud_duke_auto {

    meta:
        atk_type = "win.cloud_duke."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.cloud_duke."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cloud_duke"
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
        $sequence_0 = { 8d4c2448 e8???????? 50 8d8c240c010000 e8???????? 8d4c2448 e8???????? }
            // n = 7, score = 800
            //   8d4c2448             | lea                 ecx, [esp + 0x48]
            //   e8????????           |                     
            //   50                   | push                eax
            //   8d8c240c010000       | lea                 ecx, [esp + 0x10c]
            //   e8????????           |                     
            //   8d4c2448             | lea                 ecx, [esp + 0x48]
            //   e8????????           |                     

        $sequence_1 = { 8d8c240c010000 e8???????? 8d4c2460 e8???????? }
            // n = 4, score = 800
            //   8d8c240c010000       | lea                 ecx, [esp + 0x10c]
            //   e8????????           |                     
            //   8d4c2460             | lea                 ecx, [esp + 0x60]
            //   e8????????           |                     

        $sequence_2 = { 83fe04 7ce3 8b45e8 4b 8ad4 }
            // n = 5, score = 800
            //   83fe04               | cmp                 esi, 4
            //   7ce3                 | jl                  0xffffffe5
            //   8b45e8               | mov                 eax, dword ptr [ebp - 0x18]
            //   4b                   | dec                 ebx
            //   8ad4                 | mov                 dl, ah

        $sequence_3 = { 8d8c24d8000000 e8???????? 51 8d442434 }
            // n = 4, score = 800
            //   8d8c24d8000000       | lea                 ecx, [esp + 0xd8]
            //   e8????????           |                     
            //   51                   | push                ecx
            //   8d442434             | lea                 eax, [esp + 0x34]

        $sequence_4 = { 50 e8???????? 8b7c2440 46 3bf7 }
            // n = 5, score = 800
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b7c2440             | mov                 edi, dword ptr [esp + 0x40]
            //   46                   | inc                 esi
            //   3bf7                 | cmp                 esi, edi

        $sequence_5 = { eb0a 8b9dd8fbffff eb02 8bde 8b85e8fbffff 8d95e4fbffff 52 }
            // n = 7, score = 800
            //   eb0a                 | jmp                 0xc
            //   8b9dd8fbffff         | mov                 ebx, dword ptr [ebp - 0x428]
            //   eb02                 | jmp                 4
            //   8bde                 | mov                 ebx, esi
            //   8b85e8fbffff         | mov                 eax, dword ptr [ebp - 0x418]
            //   8d95e4fbffff         | lea                 edx, [ebp - 0x41c]
            //   52                   | push                edx

        $sequence_6 = { 85c9 7438 83fa01 7533 83bedc00000008 8d86c8000000 7202 }
            // n = 7, score = 800
            //   85c9                 | test                ecx, ecx
            //   7438                 | je                  0x3a
            //   83fa01               | cmp                 edx, 1
            //   7533                 | jne                 0x35
            //   83bedc00000008       | cmp                 dword ptr [esi + 0xdc], 8
            //   8d86c8000000         | lea                 eax, [esi + 0xc8]
            //   7202                 | jb                  4

        $sequence_7 = { 8d04450c000000 50 6a00 57 }
            // n = 4, score = 800
            //   8d04450c000000       | lea                 eax, [eax*2 + 0xc]
            //   50                   | push                eax
            //   6a00                 | push                0
            //   57                   | push                edi

        $sequence_8 = { eb02 8bce 8b5518 ff75fc 03d2 895510 }
            // n = 6, score = 800
            //   eb02                 | jmp                 4
            //   8bce                 | mov                 ecx, esi
            //   8b5518               | mov                 edx, dword ptr [ebp + 0x18]
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   03d2                 | add                 edx, edx
            //   895510               | mov                 dword ptr [ebp + 0x10], edx

        $sequence_9 = { 6806020000 50 668984241c010000 8d84241e010000 50 c744245c00000000 e8???????? }
            // n = 7, score = 800
            //   6806020000           | push                0x206
            //   50                   | push                eax
            //   668984241c010000     | mov                 word ptr [esp + 0x11c], ax
            //   8d84241e010000       | lea                 eax, [esp + 0x11e]
            //   50                   | push                eax
            //   c744245c00000000     | mov                 dword ptr [esp + 0x5c], 0
            //   e8????????           |                     

    condition:
        7 of them and filesize < 368640
}