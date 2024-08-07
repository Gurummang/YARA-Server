rule win_gameover_p2p_auto {

    meta:
        atk_type = "win.gameover_p2p."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.gameover_p2p."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gameover_p2p"
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
        $sequence_0 = { 8b01 8975dc 85c0 740f ffb09c010000 8d45d4 50 }
            // n = 7, score = 100
            //   8b01                 | mov                 eax, dword ptr [ecx]
            //   8975dc               | mov                 dword ptr [ebp - 0x24], esi
            //   85c0                 | test                eax, eax
            //   740f                 | je                  0x11
            //   ffb09c010000         | push                dword ptr [eax + 0x19c]
            //   8d45d4               | lea                 eax, [ebp - 0x2c]
            //   50                   | push                eax

        $sequence_1 = { 8d873c010000 50 889f38010000 ffd6 }
            // n = 4, score = 100
            //   8d873c010000         | lea                 eax, [edi + 0x13c]
            //   50                   | push                eax
            //   889f38010000         | mov                 byte ptr [edi + 0x138], bl
            //   ffd6                 | call                esi

        $sequence_2 = { ba???????? 8d8d70fdffff e8???????? 85c0 0f95c0 84c0 7509 }
            // n = 7, score = 100
            //   ba????????           |                     
            //   8d8d70fdffff         | lea                 ecx, [ebp - 0x290]
            //   e8????????           |                     
            //   85c0                 | test                eax, eax
            //   0f95c0               | setne               al
            //   84c0                 | test                al, al
            //   7509                 | jne                 0xb

        $sequence_3 = { 743f 53 8d442420 50 57 56 ff742428 }
            // n = 7, score = 100
            //   743f                 | je                  0x41
            //   53                   | push                ebx
            //   8d442420             | lea                 eax, [esp + 0x20]
            //   50                   | push                eax
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff742428             | push                dword ptr [esp + 0x28]

        $sequence_4 = { 7769 8a442412 0fb6c0 668901 8a442413 0fb6c0 66894102 }
            // n = 7, score = 100
            //   7769                 | ja                  0x6b
            //   8a442412             | mov                 al, byte ptr [esp + 0x12]
            //   0fb6c0               | movzx               eax, al
            //   668901               | mov                 word ptr [ecx], ax
            //   8a442413             | mov                 al, byte ptr [esp + 0x13]
            //   0fb6c0               | movzx               eax, al
            //   66894102             | mov                 word ptr [ecx + 2], ax

        $sequence_5 = { 7415 ff770c 8d442418 51 }
            // n = 4, score = 100
            //   7415                 | je                  0x17
            //   ff770c               | push                dword ptr [edi + 0xc]
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   51                   | push                ecx

        $sequence_6 = { e8???????? 8bf8 689a000000 8bd3 8bce 897c242c }
            // n = 6, score = 100
            //   e8????????           |                     
            //   8bf8                 | mov                 edi, eax
            //   689a000000           | push                0x9a
            //   8bd3                 | mov                 edx, ebx
            //   8bce                 | mov                 ecx, esi
            //   897c242c             | mov                 dword ptr [esp + 0x2c], edi

        $sequence_7 = { b9a6000000 8d5588 e8???????? e8???????? 8bc8 e8???????? 8b750c }
            // n = 7, score = 100
            //   b9a6000000           | mov                 ecx, 0xa6
            //   8d5588               | lea                 edx, [ebp - 0x78]
            //   e8????????           |                     
            //   e8????????           |                     
            //   8bc8                 | mov                 ecx, eax
            //   e8????????           |                     
            //   8b750c               | mov                 esi, dword ptr [ebp + 0xc]

        $sequence_8 = { 85c0 7548 68???????? ff35???????? ffd6 85c0 7537 }
            // n = 7, score = 100
            //   85c0                 | test                eax, eax
            //   7548                 | jne                 0x4a
            //   68????????           |                     
            //   ff35????????         |                     
            //   ffd6                 | call                esi
            //   85c0                 | test                eax, eax
            //   7537                 | jne                 0x39

        $sequence_9 = { f3ab 33db 6818010000 66ab 8d842410010000 53 50 }
            // n = 7, score = 100
            //   f3ab                 | rep stosd           dword ptr es:[edi], eax
            //   33db                 | xor                 ebx, ebx
            //   6818010000           | push                0x118
            //   66ab                 | stosw               word ptr es:[edi], ax
            //   8d842410010000       | lea                 eax, [esp + 0x110]
            //   53                   | push                ebx
            //   50                   | push                eax

    condition:
        7 of them and filesize < 598016
}