rule win_lookback_auto {

    meta:
        atk_type = "win.lookback."
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-12-06"
        version = "1"
        description = "Detects win.lookback."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lookback"
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
        $sequence_0 = { 53 8944241a 57 66894c2416 89442422 8bfa }
            // n = 6, score = 200
            //   53                   | push                ebx
            //   8944241a             | mov                 dword ptr [esp + 0x1a], eax
            //   57                   | push                edi
            //   66894c2416           | mov                 word ptr [esp + 0x16], cx
            //   89442422             | mov                 dword ptr [esp + 0x22], eax
            //   8bfa                 | mov                 edi, edx

        $sequence_1 = { 8b7c241c 33ed 8b473c 8b443878 03c7 8b5024 }
            // n = 6, score = 200
            //   8b7c241c             | mov                 edi, dword ptr [esp + 0x1c]
            //   33ed                 | xor                 ebp, ebp
            //   8b473c               | mov                 eax, dword ptr [edi + 0x3c]
            //   8b443878             | mov                 eax, dword ptr [eax + edi + 0x78]
            //   03c7                 | add                 eax, edi
            //   8b5024               | mov                 edx, dword ptr [eax + 0x24]

        $sequence_2 = { 55 8bec 51 53 c745fc00000000 b801000000 }
            // n = 6, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   b801000000           | mov                 eax, 1

        $sequence_3 = { c3 5e 5d 33c0 5b 81c410070000 c3 }
            // n = 7, score = 200
            //   c3                   | ret                 
            //   5e                   | pop                 esi
            //   5d                   | pop                 ebp
            //   33c0                 | xor                 eax, eax
            //   5b                   | pop                 ebx
            //   81c410070000         | add                 esp, 0x710
            //   c3                   | ret                 

        $sequence_4 = { 3c01 893d???????? 893d???????? 752e }
            // n = 4, score = 200
            //   3c01                 | cmp                 al, 1
            //   893d????????         |                     
            //   893d????????         |                     
            //   752e                 | jne                 0x30

        $sequence_5 = { c644240800 88442415 e8???????? 8d4c240c 89442408 51 }
            // n = 6, score = 200
            //   c644240800           | mov                 byte ptr [esp + 8], 0
            //   88442415             | mov                 byte ptr [esp + 0x15], al
            //   e8????????           |                     
            //   8d4c240c             | lea                 ecx, [esp + 0xc]
            //   89442408             | mov                 dword ptr [esp + 8], eax
            //   51                   | push                ecx

        $sequence_6 = { 8d5108 d1e8 85c0 7e33 }
            // n = 4, score = 200
            //   8d5108               | lea                 edx, [ecx + 8]
            //   d1e8                 | shr                 eax, 1
            //   85c0                 | test                eax, eax
            //   7e33                 | jle                 0x35

        $sequence_7 = { 74a7 8b06 85c0 757b }
            // n = 4, score = 200
            //   74a7                 | je                  0xffffffa9
            //   8b06                 | mov                 eax, dword ptr [esi]
            //   85c0                 | test                eax, eax
            //   757b                 | jne                 0x7d

        $sequence_8 = { 52 8d442418 57 50 68???????? 57 57 }
            // n = 7, score = 200
            //   52                   | push                edx
            //   8d442418             | lea                 eax, [esp + 0x18]
            //   57                   | push                edi
            //   50                   | push                eax
            //   68????????           |                     
            //   57                   | push                edi
            //   57                   | push                edi

        $sequence_9 = { 55 8bec 51 53 c745fc00000000 b801000000 0fa2 }
            // n = 7, score = 200
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   51                   | push                ecx
            //   53                   | push                ebx
            //   c745fc00000000       | mov                 dword ptr [ebp - 4], 0
            //   b801000000           | mov                 eax, 1
            //   0fa2                 | cpuid               

    condition:
        7 of them and filesize < 131072
}