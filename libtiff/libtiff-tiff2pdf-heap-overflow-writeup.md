# tiff2pdf Heap Buffer Overflow in libtiff before 4.7.1

## Summary

A heap-buffer-overflow exists in the `tiff2pdf` utility shipped with libtiff before 4.7.1.

The issue is in `tools/tiff2pdf.c:t2p_readwrite_pdf_image()`, in the JPEG raw passthrough path. BigTIFF `StripByteCounts` values are read as 64-bit values, but the maximum strip length was stored in a 32-bit `max_striplength` variable. A crafted BigTIFF file can therefore cause the strip byte count to be truncated before allocation, leading to an undersized heap allocation followed by a much larger raw strip read into that buffer.

The issue was confirmed with AddressSanitizer on libtiff 4.5.0. The confirmed impact is a process crash / denial of service. Because this is a heap memory corruption bug and the overflow data is derived from attacker-controlled file contents, downstream maintainers should treat it as a memory-corruption risk while completing their own exploitability assessment.

## Reporters

- Zixiang Zhou, School of Computer Science and Technology, University of Science and Technology of China, `zkd25zzx@mail.ustc.edu.cn`
- Jinbao Chen, School of Computer Science and Technology, University of Science and Technology of China, `zkd18cjb@mail.ustc.edu.cn`

## Problem Type

- CWE-197: Numeric Truncation Error
- CWE-122: Heap-based Buffer Overflow

## Affected Versions

- Confirmed affected with ASan: libtiff 4.5.0
- Vulnerable source pattern observed: libtiff 3.9.0 through 4.7.0
- First upstream release where this specific truncation appears fixed: libtiff 4.7.1
- Current upstream master / 4.7.2: appears fixed for this specific issue

Affected component:

- Utility: `tiff2pdf`
- Source file: `tools/tiff2pdf.c`
- Function: `t2p_readwrite_pdf_image()`

The observed vulnerable path requires `tiff2pdf` to process a crafted BigTIFF file in the JPEG raw passthrough path. In our test case, the `-m 0` option was used to disable the default allocation limit:

```bash
tiff2pdf -m 0 -o out.pdf poc.tif
```

Without disabling or raising the allocation limit, the tested libtiff 4.5.0 build rejects the crafted input before reaching the vulnerable copy. This lowers practical exploitability for default interactive command-line use, but automated conversion systems that process untrusted TIFF files with the memory limit disabled or raised may still be exposed.

## Root Cause

In libtiff 4.5.0, the relevant code uses a 32-bit `max_striplength` even though BigTIFF strip byte counts can be 64-bit:

```c
uint64_t *sbc;
uint32_t max_striplength = 0;
...
TIFFGetField(input, TIFFTAG_STRIPBYTECOUNTS, &sbc);
for (i = 0; i < stripcount; i++)
{
    if (sbc[i] > max_striplength)
        max_striplength = sbc[i];
}
stripbuffer = (unsigned char *)_TIFFmalloc(max_striplength);
...
striplength = TIFFReadRawStrip(input, i, (tdata_t)stripbuffer, -1);
```

For a crafted BigTIFF file with a large `StripByteCounts` value, the 64-bit strip byte count can be truncated when assigned to `max_striplength`. This causes `tiff2pdf` to allocate a much smaller buffer than the raw strip size subsequently read by `TIFFReadRawStrip()`.

One tested trigger condition used a BigTIFF `StripByteCounts` value of `0x100000005`. This value is read as `4294967301`, but truncates to `5` when stored in a 32-bit `max_striplength`. The resulting allocation is 5 bytes, while the later raw strip read attempts to copy the full strip byte count into that buffer.

## Verification

The issue was verified locally with an AddressSanitizer build of libtiff 4.5.0:

```bash
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1 \
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
tiff2pdf -m 0 -o out.pdf poc.tif
```

AddressSanitizer reported:

```text
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 4294967301

#1 _TIFFmemcpy libtiff/tif_unix.c:345
#2 TIFFReadRawStrip1 libtiff/tif_read.c:652
#3 TIFFReadRawStrip libtiff/tif_read.c:725
#4 t2p_readwrite_pdf_image tools/tiff2pdf.c:2744
#5 t2p_write_pdf tools/tiff2pdf.c:6295

allocated by:
#1 _TIFFmalloc libtiff/tif_unix.c:326
#2 t2p_readwrite_pdf_image tools/tiff2pdf.c:2729
```

A PoC generator and full ASan logs are available privately to upstream maintainers and distribution security teams for triage. They are intentionally not included in this public writeup.

## Fixed Version

The first upstream release where this specific truncation appears fixed is libtiff 4.7.1.

The relevant change was introduced by upstream commit `67fd283d276f09db54dc39b9ef7b979d4b45c4b1`, from merge request `!729`, which changed `max_striplength` from `uint32_t` to `uint64_t` in `tools/tiff2pdf.c`.

References:

- Fixing commit: <https://gitlab.com/libtiff/libtiff/-/commit/67fd283d276f09db54dc39b9ef7b979d4b45c4b1>
- Merge request: <https://gitlab.com/libtiff/libtiff/-/merge_requests/729>

The upstream commit was titled as an MSVC warning cleanup and does not appear to have been published as a security fix. We could not find a public CVE, advisory, issue, or merge request that clearly covers this exact BigTIFF `StripByteCounts` 64-bit to 32-bit truncation root cause.

## Distribution Impact

Distribution packages should be considered potentially affected when all of the following are true:

- The packaged libtiff source is based on libtiff before 4.7.1, or otherwise still has a 32-bit `max_striplength` in `tools/tiff2pdf.c`.
- The distribution builds and ships the `tiff2pdf` command-line utility.
- The distribution has not backported commit `67fd283d276f09db54dc39b9ef7b979d4b45c4b1` or an equivalent fix.

Initial downstream checks on 2026-06-29 indicated that some Debian and Ubuntu package sources still contained the vulnerable 32-bit `max_striplength` pattern while shipping `tiff2pdf`. Those findings should be confirmed by the respective distribution security teams against their fully patched package sources.

## Severity

Suggested initial severity: Medium for the confirmed CLI-triggered impact; potentially High in automated conversion services that process untrusted TIFF files with the allocation limit disabled or raised.

Confirmed impact:

- Heap-buffer-overflow write in `tiff2pdf`
- Process crash / denial of service confirmed with ASan
- Memory corruption risk

Exploitability considerations:

- The attack requires a crafted BigTIFF file to be processed by `tiff2pdf`.
- In our test case, the vulnerable path required `-m 0` to disable the default allocation limit.
- Default manual command-line use is therefore less exposed than automated conversion pipelines that process untrusted files with the memory limit disabled or raised.

Suggested conservative CVSS 3.1 framing for the confirmed impact:

```text
CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H
```

This corresponds to a local file-processing utility, user interaction, high attack complexity due to the non-default memory-limit condition observed in testing, and confirmed availability impact only. Deployments that expose `tiff2pdf` through automated processing of untrusted files may need to adjust the environmental score.

## Disclosure Timeline

- 2026-06-29: Issue reported to libtiff upstream maintainers.
- 2026-06-29: Issue reported to the Debian Security Team for downstream triage.
- 2026-06-29: Debian Security Team suggested public tracking and requesting a CVE ID after preparing a public writeup.
- 2026-06-29: Public writeup prepared.
