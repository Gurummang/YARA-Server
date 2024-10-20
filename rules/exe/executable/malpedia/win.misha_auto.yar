rule win_misha_auto {

    meta:
        atk_type = "win.misha."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.misha."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.misha"
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
        $sequence_0 = { 0fbe09 03c1 894510 8b45f8 40 8945f8 8b4510 }
            // n = 7, score = 300
            //   0fbe09               | movsx               ecx, byte ptr [ecx]
            //   03c1                 | add                 eax, ecx
            //   894510               | mov                 dword ptr [ebp + 0x10], eax
            //   8b45f8               | mov                 eax, dword ptr [ebp - 8]
            //   40                   | inc                 eax
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   8b4510               | mov                 eax, dword ptr [ebp + 0x10]

        $sequence_1 = { c20400 55 8bec 51 837d0802 7448 837d0804 }
            // n = 7, score = 300
            //   c20400               | ret                 4
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   837d0802             | cmp                 dword ptr [ebp + 8], 2
            //   7448                 | je                  0x4a
            //   837d0804             | cmp                 dword ptr [ebp + 8], 4

        $sequence_2 = { 8945dc 817d140000007e 7607 33c0 e9???????? 8b4524 }
            // n = 6, score = 300
            //   8945dc               | mov                 dword ptr [ebp - 0x24], eax
            //   817d140000007e       | cmp                 dword ptr [ebp + 0x14], 0x7e000000
            //   7607                 | jbe                 9
            //   33c0                 | xor                 eax, eax
            //   e9????????           |                     
            //   8b4524               | mov                 eax, dword ptr [ebp + 0x24]

        $sequence_3 = { 32c0 5d c3 56 8bf0 eb0a 8bce }
            // n = 7, score = 300
            //   32c0                 | xor                 al, al
            //   5d                   | pop                 ebp
            //   c3                   | ret                 
            //   56                   | push                esi
            //   8bf0                 | mov                 esi, eax
            //   eb0a                 | jmp                 0xc
            //   8bce                 | mov                 ecx, esi

        $sequence_4 = { c78510ffffff04040404 c78514ffffff04040404 c78518ffffff04040404 c7851cffffff04040404 c78520ffffff05050505 c78524ffffff05050505 c78528ffffff05050505 }
            // n = 7, score = 300
            //   c78510ffffff04040404     | mov    dword ptr [ebp - 0xf0], 0x4040404
            //   c78514ffffff04040404     | mov    dword ptr [ebp - 0xec], 0x4040404
            //   c78518ffffff04040404     | mov    dword ptr [ebp - 0xe8], 0x4040404
            //   c7851cffffff04040404     | mov    dword ptr [ebp - 0xe4], 0x4040404
            //   c78520ffffff05050505     | mov    dword ptr [ebp - 0xe0], 0x5050505
            //   c78524ffffff05050505     | mov    dword ptr [ebp - 0xdc], 0x5050505
            //   c78528ffffff05050505     | mov    dword ptr [ebp - 0xd8], 0x5050505

        $sequence_5 = { 85c0 7404 2bf3 8930 b001 }
            // n = 5, score = 300
            //   85c0                 | test                eax, eax
            //   7404                 | je                  6
            //   2bf3                 | sub                 esi, ebx
            //   8930                 | mov                 dword ptr [eax], esi
            //   b001                 | mov                 al, 1

        $sequence_6 = { 8b450c 0590010000 50 e8???????? 83c414 b001 e9???????? }
            // n = 7, score = 300
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   0590010000           | add                 eax, 0x190
            //   50                   | push                eax
            //   e8????????           |                     
            //   83c414               | add                 esp, 0x14
            //   b001                 | mov                 al, 1
            //   e9????????           |                     

        $sequence_7 = { 8b4dcc 8d440104 8945cc 837d900f 0f829e000000 837d1c00 741d }
            // n = 7, score = 300
            //   8b4dcc               | mov                 ecx, dword ptr [ebp - 0x34]
            //   8d440104             | lea                 eax, [ecx + eax + 4]
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax
            //   837d900f             | cmp                 dword ptr [ebp - 0x70], 0xf
            //   0f829e000000         | jb                  0xa4
            //   837d1c00             | cmp                 dword ptr [ebp + 0x1c], 0
            //   741d                 | je                  0x1f

        $sequence_8 = { 50 e8???????? 8b5508 56 6a1c 59 }
            // n = 6, score = 300
            //   50                   | push                eax
            //   e8????????           |                     
            //   8b5508               | mov                 edx, dword ptr [ebp + 8]
            //   56                   | push                esi
            //   6a1c                 | push                0x1c
            //   59                   | pop                 ecx

        $sequence_9 = { 8b4514 e8???????? 0fb64524 85c0 7456 6a00 68ffffff7f }
            // n = 7, score = 300
            //   8b4514               | mov                 eax, dword ptr [ebp + 0x14]
            //   e8????????           |                     
            //   0fb64524             | movzx               eax, byte ptr [ebp + 0x24]
            //   85c0                 | test                eax, eax
            //   7456                 | je                  0x58
            //   6a00                 | push                0
            //   68ffffff7f           | push                0x7fffffff

    condition:
        7 of them and filesize < 710656
}