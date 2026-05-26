"""IDA helper for the packed SabbatOfTheWitch.exe database.

Run in IDA after loading the current executable or the runtime-unpacked dump.
It labels the known binder and TVP/XP3 RTTI/vtable anchors discovered during
static analysis. The names are intentionally anchor-style because the packed
.text code is not yet reliable for function-level analysis.
"""

from __future__ import annotations

import ida_bytes
import ida_funcs
import ida_name
import idaapi


LABELS = {
    0x8E4310: "bind_entry_stub",
    0x8E4390: "bind_unpack_loader",
    0x639653: "suspected_unpacked_oep_639653",
    0x7282D4: "vt_tTVPStorageProvider",
    0x72833C: "vt_tTVPFileMedia",
    0x7283EC: "vt_tTVPArchive",
    0x728510: "vt_tTVPXP3Archive",
    0x728524: "vt_tTVPXP3ArchiveStream",
    0x7285F4: "vt_tTVPCryptoFilter",
    0x728608: "vt_tTVPStorageMedia",
    0x728634: "vt_tTVPBasicCryptoFilter",
    0x728648: "vt_tTVPResourceStorageMedia",
    0x776B34: "rtti_tTVPStorageProvider",
    0x776CFC: "rtti_tTVPFileMedia",
    0x776D80: "rtti_tTVPArchive",
    0x776E2C: "rtti_tTVPXP3ArchiveStream",
    0x776E7C: "rtti_tTVPXP3Archive",
    0x776EB0: "rtti_tTVPBasicCryptoFilter",
    0x776F0C: "rtti_tTVPStorageMedia",
    0x776F2C: "rtti_tTVPCryptoFilter",
    0x776F6C: "rtti_tTVPResourceStorageMedia",
}


COMMENTS = {
    0x8E4310: ".bind entry stub; calls bind_unpack_loader and returns patched OEP.",
    0x8E4390: (
        "Binder/unpack loader. Static analysis shows header magic 0xC0DEC0DF, "
        "TEA-like block decrypt, import rebuild, section protection changes, "
        "then transfer to the unpacked image."
    ),
    0x639653: (
        "Computed original entry point from bind header: image base 0x400000 + "
        "OEP RVA 0x239653. Dump around runtime transfer before deeper XP3 analysis."
    ),
    0x728510: "tTVPXP3Archive vtable anchor. Revisit in unpacked dump for real methods.",
    0x728524: "tTVPXP3ArchiveStream vtable anchor. Likely segment read/seek stream methods.",
    0x728634: "tTVPBasicCryptoFilter vtable anchor. Check after dump for content filter logic.",
}


def set_label(ea: int, name: str) -> None:
    ida_name.set_name(ea, name, ida_name.SN_CHECK | ida_name.SN_FORCE)


def set_comment(ea: int, text: str) -> None:
    ida_bytes.set_cmt(ea, text, False)
    func = ida_funcs.get_func(ea)
    if func:
        ida_funcs.set_func_cmt(func, text, False)


def main() -> None:
    for ea, name in LABELS.items():
        if idaapi.getseg(ea):
            set_label(ea, name)

    for ea, text in COMMENTS.items():
        if idaapi.getseg(ea):
            set_comment(ea, text)

    print(f"Applied {len(LABELS)} labels and {len(COMMENTS)} comments.")


if __name__ == "__main__":
    main()
