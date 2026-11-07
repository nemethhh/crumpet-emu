"""LK layer: the 2025 signed-unlock hunting surface.

session.py generalizes the donor lk-emu LKEmu harness into the session-based
LkSession (surgical entry mode: single named-function calls, donor platform
stub table, single-instruction fault model at the RSA gate). battery.py is
the donor scenario battery (keydump / vcode / vunlock / otu / otu-glitch /
bootimg / certdriver / b64 / otucode-derive / flash-e2e), hostcrypto.py the
pure-stdlib RSA-PSS crafting kit, seeds.json the committed export of the
donor audit-pinned function table. Donor: tools/lk-emu (see module headers).
"""
