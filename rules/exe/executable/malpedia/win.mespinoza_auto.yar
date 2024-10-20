rule win_mespinoza_auto {

    meta:
        atk_type = "win.mespinoza."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.mespinoza."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mespinoza"
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
        $sequence_0 = { 8d4d9c e8???????? 83eb01 75e7 8b4d0c }
            // n = 5, score = 200
            //   8d4d9c               | lea                 ecx, [ebp - 0x64]
            //   e8????????           |                     
            //   83eb01               | sub                 ebx, 1
            //   75e7                 | jne                 0xffffffe9
            //   8b4d0c               | mov                 ecx, dword ptr [ebp + 0xc]

        $sequence_1 = { 897d0c c645fc01 85ff 7446 56 8bcf e8???????? }
            // n = 7, score = 200
            //   897d0c               | mov                 dword ptr [ebp + 0xc], edi
            //   c645fc01             | mov                 byte ptr [ebp - 4], 1
            //   85ff                 | test                edi, edi
            //   7446                 | je                  0x48
            //   56                   | push                esi
            //   8bcf                 | mov                 ecx, edi
            //   e8????????           |                     

        $sequence_2 = { 8b4dc4 8b7dc0 6aff 6a01 }
            // n = 4, score = 200
            //   8b4dc4               | mov                 ecx, dword ptr [ebp - 0x3c]
            //   8b7dc0               | mov                 edi, dword ptr [ebp - 0x40]
            //   6aff                 | push                -1
            //   6a01                 | push                1

        $sequence_3 = { 891f 895f04 6a01 895dfc e8???????? 59 894704 }
            // n = 7, score = 200
            //   891f                 | mov                 dword ptr [edi], ebx
            //   895f04               | mov                 dword ptr [edi + 4], ebx
            //   6a01                 | push                1
            //   895dfc               | mov                 dword ptr [ebp - 4], ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   894704               | mov                 dword ptr [edi + 4], eax

        $sequence_4 = { 03c1 3bc1 7334 8bde 8bf1 2bf0 }
            // n = 6, score = 200
            //   03c1                 | add                 eax, ecx
            //   3bc1                 | cmp                 eax, ecx
            //   7334                 | jae                 0x36
            //   8bde                 | mov                 ebx, esi
            //   8bf1                 | mov                 esi, ecx
            //   2bf0                 | sub                 esi, eax

        $sequence_5 = { 75f9 2bd6 8db5f8feffff 8d5e01 8a06 46 84c0 }
            // n = 7, score = 200
            //   75f9                 | jne                 0xfffffffb
            //   2bd6                 | sub                 edx, esi
            //   8db5f8feffff         | lea                 esi, [ebp - 0x108]
            //   8d5e01               | lea                 ebx, [esi + 1]
            //   8a06                 | mov                 al, byte ptr [esi]
            //   46                   | inc                 esi
            //   84c0                 | test                al, al

        $sequence_6 = { 83e03f 6bd030 895de4 8b049d00b04700 8945d4 8955e8 8a5c1029 }
            // n = 7, score = 200
            //   83e03f               | and                 eax, 0x3f
            //   6bd030               | imul                edx, eax, 0x30
            //   895de4               | mov                 dword ptr [ebp - 0x1c], ebx
            //   8b049d00b04700       | mov                 eax, dword ptr [ebx*4 + 0x47b000]
            //   8945d4               | mov                 dword ptr [ebp - 0x2c], eax
            //   8955e8               | mov                 dword ptr [ebp - 0x18], edx
            //   8a5c1029             | mov                 bl, byte ptr [eax + edx + 0x29]

        $sequence_7 = { 8b6c240c 56 57 55 8bf9 e8???????? 8b37 }
            // n = 7, score = 200
            //   8b6c240c             | mov                 ebp, dword ptr [esp + 0xc]
            //   56                   | push                esi
            //   57                   | push                edi
            //   55                   | push                ebp
            //   8bf9                 | mov                 edi, ecx
            //   e8????????           |                     
            //   8b37                 | mov                 esi, dword ptr [edi]

        $sequence_8 = { 64a300000000 8965f0 8b7508 8b7d0c 8975ec c745fc00000000 0f1f440000 }
            // n = 7, score = 200
            //   64a300000000         | mov                 dword ptr fs:[0], eax
            //   8965f0               | mov                 dword ptr [ebp - 0x10], esp
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8b7d0c               | mov                 edi, dword ptr [ebp + 0xc]
            //   8975ec               | mov                 dword ptr [ebp - 0x14], esi
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   0f1f440000           | nop                 dword ptr [eax + eax]

        $sequence_9 = { 8bc3 2bc2 894714 8b7508 8bce e8???????? 84c0 }
            // n = 7, score = 200
            //   8bc3                 | mov                 eax, ebx
            //   2bc2                 | sub                 eax, edx
            //   894714               | mov                 dword ptr [edi + 0x14], eax
            //   8b7508               | mov                 esi, dword ptr [ebp + 8]
            //   8bce                 | mov                 ecx, esi
            //   e8????????           |                     
            //   84c0                 | test                al, al

    condition:
        7 of them and filesize < 1091584
}