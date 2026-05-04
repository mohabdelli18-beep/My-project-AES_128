# aes_visualizer_tk.py
# AES-128 Step-by-step Visualizer (Tkinter) with Key Schedule steps
# Educational implementation (no external crypto libs)

import tkinter as tk
from tkinter import ttk, messagebox

# ----------------------------
# AES tables (S-box, Rcon)
# ----------------------------
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

RCON = [0x00, 0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]

# ----------------------------
# Helpers
# ----------------------------
def fmt_byte(x: int) -> str:
    return f"{x & 0xFF:02x}"

def hex_to_bytes_16(s: str) -> bytes:
    s = s.strip().lower().replace(" ", "")
    if len(s) != 32:
        raise ValueError("يجب أن يكون بالضبط 32 حرف hex (16 بايت).")
    try:
        b = bytes.fromhex(s)
    except ValueError:
        raise ValueError("إدخال الـ hex غير صالح.")
    if len(b) != 16:
        raise ValueError("يجب أن يكون 16 بايت.")
    return b

def bytes_to_state(b16: bytes):
    state = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = b16[c*4 + r]
    return state

def state_to_bytes(state):
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c*4 + r] = state[r][c] & 0xFF
    return bytes(out)

def state_to_hex(state) -> str:
    return state_to_bytes(state).hex()

def clone_state(state):
    return [row[:] for row in state]

def clone_word(w):
    return w[:] if w else None

def words_to_roundkey_state(words4):
    # words4: list of 4 words, each 4 bytes -> 16 bytes, then to state (col-major)
    b = bytearray()
    for w in words4:
        b.extend(w)
    return bytes_to_state(bytes(b))

# ----------------------------
# AES operations
# ----------------------------
def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]
    return state

def shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]
    return state

def gmul(a, b):
    a &= 0xFF
    b &= 0xFF
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

def mix_single_column(col):
    a0,a1,a2,a3 = col
    return [
        (gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3) & 0xFF,
        (a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3) & 0xFF,
        (a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3)) & 0xFF,
        (gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2)) & 0xFF,
    ]

def mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            state[r][c] = mixed[r]
    return state

def add_round_key(state, round_key_state):
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key_state[r][c]
    return state

# ----------------------------
# Key schedule helpers
# ----------------------------
def rot_word(word4):
    return word4[1:] + word4[:1]

def sub_word(word4):
    return [SBOX[b] for b in word4]

def xor_words(a, b):
    return [(x ^ y) & 0xFF for x, y in zip(a, b)]

# ----------------------------
# Snapshot model
# ----------------------------
class Snapshot:
    """
    kind:
      - "cipher": state meaningful (encryption steps)
      - "keyschedule": state may be None; key_words holds interesting words
    """
    def __init__(self, kind, round_idx, step_name,
                 state=None, round_key=None,
                 key_words=None, note=""):
        self.kind = kind
        self.round_idx = round_idx
        self.step_name = step_name
        self.state = clone_state(state) if state is not None else None
        self.round_key = clone_state(round_key) if round_key is not None else None
        # key_words: list of dicts, each: {"label": str, "word": [b0,b1,b2,b3]}
        self.key_words = []
        if key_words:
            for item in key_words:
                self.key_words.append({"label": item["label"], "word": clone_word(item["word"])})
        self.note = note

# ----------------------------
# Key schedule with steps (AES-128)
# ----------------------------
def expand_key_128_with_steps(key_bytes_16: bytes):
    key = list(key_bytes_16)
    w = []
    ks_snaps = []

    # initial words
    for i in range(4):
        w.append(key[4*i:4*i+4])

    # snapshot: initial key words
    ks_snaps.append(Snapshot(
        "keyschedule", 0, "KeySchedule: Initial Words (w0..w3)",
        state=None, round_key=words_to_roundkey_state(w[0:4]),
        key_words=[
            {"label":"w0", "word": w[0]},
            {"label":"w1", "word": w[1]},
            {"label":"w2", "word": w[2]},
            {"label":"w3", "word": w[3]},
        ],
        note="يتم تقسيم المفتاح الأولي إلى 4 كلمات مكونة من 4 بايت (w0..w3)."
    ))

    # generate w4..w43
    for r in range(1, 11):
        i = r * 4  # start word index of this round
        prev = w[i-1][:]  # w[i-1]

        rot = rot_word(prev)
        ks_snaps.append(Snapshot(
            "keyschedule", r, f"KeySchedule R{r}: RotWord(w{i-1})",
            round_key=None,
            key_words=[{"label": f"w{i-1}", "word": prev}, {"label": "RotWord", "word": rot}],
            note=f"RotWord: تدوير لليسار بمقدار بايت واحد على w{i-1}."
        ))

        sub = sub_word(rot)
        ks_snaps.append(Snapshot(
            "keyschedule", r, f"KeySchedule R{r}: SubWord(RotWord)",
            round_key=None,
            key_words=[{"label": "RotWord", "word": rot}, {"label": "SubWord", "word": sub}],
            note="SubWord: يتم تمرير كل بايت عبر S-Box."
        ))

        temp = sub[:]
        temp[0] ^= RCON[r]
        ks_snaps.append(Snapshot(
            "keyschedule", r, f"KeySchedule R{r}: XOR Rcon[{r}]",
            round_key=None,
            key_words=[{"label": "SubWord", "word": sub}, {"label": f"⊕Rcon[{r}]", "word": temp}],
            note=f"Rcon[{r}] يتم عمل XOR على البايت الأول فقط. (Rcon={fmt_byte(RCON[r])} 00 00 00)"
        ))

        w_i = xor_words(w[i-4], temp)   # w[i]
        w.append(w_i)
        ks_snaps.append(Snapshot(
            "keyschedule", r, f"KeySchedule R{r}: w{i} = w{i-4} ⊕ temp",
            round_key=None,
            key_words=[{"label": f"w{i-4}", "word": w[i-4]}, {"label":"temp", "word": temp}, {"label": f"w{i}", "word": w_i}],
            note=f"إنشاء w{i} عن طريق عمل XOR بين w{i-4} و temp."
        ))

        for k in range(1, 4):
            wk = xor_words(w[i+k-4], w[i+k-1])  # w[i+k] = w[i+k-4] ⊕ w[i+k-1]
            w.append(wk)
            ks_snaps.append(Snapshot(
                "keyschedule", r, f"KeySchedule R{r}: w{i+k} = w{i+k-4} ⊕ w{i+k-1}",
                round_key=None,
                key_words=[
                    {"label": f"w{i+k-4}", "word": w[i+k-4]},
                    {"label": f"w{i+k-1}", "word": w[i+k-1]},
                    {"label": f"w{i+k}", "word": wk},
                ],
                note=f"إنشاء w{i+k} عن طريق عمل XOR للكلمتين السابقتين."
            ))

        # snapshot: completed round key r (words i..i+3)
        rk_words = w[i:i+4]
        rk_state = words_to_roundkey_state(rk_words)
        ks_snaps.append(Snapshot(
            "keyschedule", r, f"KeySchedule R{r}: RoundKey{r} (w{i}..w{i+3})",
            round_key=rk_state,
            key_words=[
                {"label": f"w{i}", "word": rk_words[0]},
                {"label": f"w{i+1}", "word": rk_words[1]},
                {"label": f"w{i+2}", "word": rk_words[2]},
                {"label": f"w{i+3}", "word": rk_words[3]},
            ],
            note=f"يتم إنشاء RoundKey{r} من الكلمات الأربع w{i}..w{i+3}."
        ))

    # build round keys list
    round_keys = []
    for r in range(11):
        rk_words = w[r*4:r*4+4]
        round_keys.append(words_to_roundkey_state(rk_words))

    return round_keys, ks_snaps

# ----------------------------
# Encryption snapshots (AES-128)
# ----------------------------
def aes128_snapshots(plaintext16: bytes, key16: bytes):
    state0 = bytes_to_state(plaintext16)

    round_keys, ks_snaps = expand_key_128_with_steps(key16)

    snaps = []
    # put key schedule steps first
    snaps.extend(ks_snaps)

    # then cipher steps
    snaps.append(Snapshot(
        "cipher", 0, "Input",
        state=state0, round_key=round_keys[0],
        note="الـ State الأولي من النص الواضح (plaintext) (ترتيب عمودي). RoundKey0 هو نفسه المفتاح الرئيسي."
    ))

    # Round 0: AddRoundKey
    s = clone_state(state0)
    add_round_key(s, round_keys[0])
    snaps.append(Snapshot(
        "cipher", 0, "AddRoundKey",
        state=s, round_key=round_keys[0],
        note="Round 0: State ⊕ RoundKey0"
    ))

    cur = s
    # Rounds 1..9
    for r in range(1, 10):
        s1 = clone_state(cur)
        sub_bytes(s1)
        snaps.append(Snapshot("cipher", r, "SubBytes", state=s1, round_key=round_keys[r],
                              note="يتم استبدال كل بايت باستخدام S-Box."))

        s2 = clone_state(s1)
        shift_rows(s2)
        snaps.append(Snapshot("cipher", r, "ShiftRows", state=s2, round_key=round_keys[r],
                              note="الصفوف: يتم إزاحة الصف i إلى اليسار بمقدار i بايت."))

        s3 = clone_state(s2)
        mix_columns(s3)
        snaps.append(Snapshot("cipher", r, "MixColumns", state=s3, round_key=round_keys[r],
                              note="يتم خلط كل عمود عن طريق ضرب المصفوفات في GF(2^8)."))

        s4 = clone_state(s3)
        add_round_key(s4, round_keys[r])
        snaps.append(Snapshot("cipher", r, "AddRoundKey", state=s4, round_key=round_keys[r],
                              note=f"Round {r}: State ⊕ RoundKey{r}"))

        cur = s4

    # Round 10 (no MixColumns)
    r = 10
    s1 = clone_state(cur)
    sub_bytes(s1)
    snaps.append(Snapshot("cipher", r, "SubBytes", state=s1, round_key=round_keys[r],
                          note="Round 10: SubBytes"))

    s2 = clone_state(s1)
    shift_rows(s2)
    snaps.append(Snapshot("cipher", r, "ShiftRows", state=s2, round_key=round_keys[r],
                          note="Round 10: ShiftRows"))

    s3 = clone_state(s2)
    add_round_key(s3, round_keys[r])
    snaps.append(Snapshot("cipher", r, "AddRoundKey (Final)", state=s3, round_key=round_keys[r],
                          note="Round 10: AddRoundKey (بدون MixColumns). المخرجات = Ciphertext"))

    ciphertext = state_to_bytes(s3)
    return snaps, ciphertext

# ----------------------------
# GUI
# ----------------------------
class AESVisualizerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES-128 Step-by-step Visualizer (Tkinter) + Key Schedule")
        self.geometry("1020x650")
        self.minsize(940, 560)

        self.snaps = []
        self.ciphertext = b""
        self.idx = 0

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Plaintext (hex, 16 bytes / 32 chars):").grid(row=0, column=0, sticky="w")
        self.plain_entry = ttk.Entry(top, width=50)
        self.plain_entry.grid(row=0, column=1, padx=8, sticky="w")
        self.plain_entry.insert(0, "3243f6a8885a308d313198a2e0370734")

        ttk.Label(top, text="Key (hex, 16 bytes / 32 chars):").grid(row=1, column=0, sticky="w")
        self.key_entry = ttk.Entry(top, width=50)
        self.key_entry.grid(row=1, column=1, padx=8, sticky="w")
        self.key_entry.insert(0, "2b7e151628aed2a6abf7158809cf4f3c")

        self.run_btn = ttk.Button(top, text="Run / Generate Steps", command=self.on_run)
        self.run_btn.grid(row=0, column=2, rowspan=2, padx=10, sticky="ns")

        main = ttk.Frame(self, padding=10)
        main.pack(fill="both", expand=True)

        # Left: step list
        left = ttk.Frame(main)
        left.pack(side="left", fill="y", padx=(0, 10))

        ttk.Label(left, text="Steps").pack(anchor="w")
        self.steps = tk.Listbox(left, height=30, width=44, exportselection=False)
        self.steps.pack(fill="y", expand=False)
        self.steps.bind("<<ListboxSelect>>", self.on_step_select)

        # Right: grids + info
        right = ttk.Frame(main)
        right.pack(side="left", fill="both", expand=True)

        header = ttk.Frame(right)
        header.pack(fill="x")

        self.step_title = ttk.Label(header, text="—", font=("TkDefaultFont", 12, "bold"))
        self.step_title.pack(side="left", anchor="w")

        self.round_label = ttk.Label(header, text="", font=("TkDefaultFont", 10))
        self.round_label.pack(side="right", anchor="e")

        grids = ttk.Frame(right)
        grids.pack(fill="x", pady=(10, 0))

        # State grid
        self.state_frame = ttk.LabelFrame(grids, text="State (4×4)")
        self.state_frame.pack(side="left", padx=(0, 10))
        self.state_cells = [[self._make_cell(self.state_frame, r, c) for c in range(4)] for r in range(4)]

        # Right grid: RoundKey (or KeySchedule words)
        self.key_frame = ttk.LabelFrame(grids, text="Round Key / Key Schedule (4×4)")
        self.key_frame.pack(side="left")
        self.key_cells = [[self._make_cell(self.key_frame, r, c) for c in range(4)] for r in range(4)]

        # Controls
        controls = ttk.Frame(right)
        controls.pack(fill="x", pady=10)

        self.prev_btn = ttk.Button(controls, text="◀ Prev", command=self.on_prev, state="disabled")
        self.prev_btn.pack(side="left")

        self.next_btn = ttk.Button(controls, text="Next ▶", command=self.on_next, state="disabled")
        self.next_btn.pack(side="left", padx=(8, 0))

        self.pos_label = ttk.Label(controls, text="")
        self.pos_label.pack(side="left", padx=(12, 0))

        # Output
        out_frame = ttk.LabelFrame(right, text="Output")
        out_frame.pack(fill="x", pady=(8, 0))
        self.ct_var = tk.StringVar(value="Ciphertext: —")
        ttk.Label(out_frame, textvariable=self.ct_var).pack(anchor="w", padx=8, pady=6)

        # Notes
        note_frame = ttk.LabelFrame(right, text="Explanation")
        note_frame.pack(fill="both", expand=True, pady=(10, 0))

        self.note_text = tk.Text(note_frame, height=10, wrap="word")
        self.note_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.note_text.configure(state="disabled")

        tip = ttk.Label(self, text="التمييز (Highlight) = تغيير مقارنة بالمرحلة السابقة (لـ State أو لجدول المفاتيح).", foreground="#555")
        tip.pack(anchor="w", padx=12, pady=(0, 8))

    def _make_cell(self, parent, r, c):
        lbl = tk.Label(parent, text="--", width=4, height=2, relief="solid", borderwidth=1, font=("Consolas", 12))
        lbl.grid(row=r, column=c, padx=2, pady=2)
        return lbl

    def on_run(self):
        try:
            pt = hex_to_bytes_16(self.plain_entry.get())
            key = hex_to_bytes_16(self.key_entry.get())
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return

        try:
            self.snaps, self.ciphertext = aes128_snapshots(pt, key)
        except Exception as e:
            messagebox.showerror("AES Error", f"مشكلة في حسابات AES:\n{e}")
            return

        self.steps.delete(0, tk.END)
        for i, s in enumerate(self.snaps):
            kind = "KS" if s.kind == "keyschedule" else "AES"
            self.steps.insert(tk.END, f"{i:03d} | {kind} | R{s.round_idx:02d} | {s.step_name}")

        self.idx = 0
        self.steps.selection_clear(0, tk.END)
        self.steps.selection_set(0)
        self.steps.activate(0)

        self.prev_btn.configure(state="normal")
        self.next_btn.configure(state="normal")

        self.ct_var.set(f"Ciphertext: {self.ciphertext.hex()}")
        self.show_snapshot(0)

    def on_step_select(self, _evt):
        sel = self.steps.curselection()
        if not sel:
            return
        self.show_snapshot(sel[0])

    def on_prev(self):
        if not self.snaps:
            return
        new = max(0, self.idx - 1)
        self.steps.selection_clear(0, tk.END)
        self.steps.selection_set(new)
        self.steps.activate(new)
        self.show_snapshot(new)

    def on_next(self):
        if not self.snaps:
            return
        new = min(len(self.snaps) - 1, self.idx + 1)
        self.steps.selection_clear(0, tk.END)
        self.steps.selection_set(new)
        self.steps.activate(new)
        self.show_snapshot(new)

    def _set_note(self, text):
        self.note_text.configure(state="normal")
        self.note_text.delete("1.0", tk.END)
        self.note_text.insert(tk.END, text)
        self.note_text.configure(state="disabled")

    def _clear_grid(self, grid_cells):
        for r in range(4):
            for c in range(4):
                grid_cells[r][c].configure(text="--", bg="white")

    def _render_matrix(self, grid_cells, matrix, prev_matrix=None):
        for r in range(4):
            for c in range(4):
                v = matrix[r][c]
                txt = fmt_byte(v)
                cell = grid_cells[r][c]
                cell.configure(text=txt)
                changed = (prev_matrix is not None and prev_matrix[r][c] != v)
                cell.configure(bg="#fff2a8" if changed else "white")

    def _render_words_as_4x4(self, grid_cells, key_words, prev_words=None):
        """
        Show up to 4 words (each 4 bytes) as 4x4:
          columns correspond to words; rows are bytes 0..3
        """
        # build matrix 4x4 filled with None
        mat = [[None]*4 for _ in range(4)]
        for c in range(4):
            if c < len(key_words):
                w = key_words[c]["word"]
                for r in range(4):
                    mat[r][c] = w[r]
            else:
                for r in range(4):
                    mat[r][c] = None

        prev_mat = None
        if prev_words is not None:
            prev_mat = [[None]*4 for _ in range(4)]
            for c in range(4):
                if c < len(prev_words):
                    w = prev_words[c]["word"]
                    for r in range(4):
                        prev_mat[r][c] = w[r]
                else:
                    for r in range(4):
                        prev_mat[r][c] = None

        for r in range(4):
            for c in range(4):
                v = mat[r][c]
                cell = grid_cells[r][c]
                if v is None:
                    cell.configure(text="--", bg="white")
                else:
                    cell.configure(text=fmt_byte(v))
                    changed = (prev_mat is not None and prev_mat[r][c] != v)
                    cell.configure(bg="#fff2a8" if changed else "white")

    def show_snapshot(self, i):
        if not (0 <= i < len(self.snaps)):
            return
        self.idx = i
        snap = self.snaps[i]

        self.step_title.configure(text=f"{snap.step_name}")
        self.round_label.configure(text=f"Round: {snap.round_idx}    Step: {i+1}/{len(self.snaps)}    Kind: {snap.kind}")
        self.pos_label.configure(text=f"Index {i} / {len(self.snaps)-1}")

        prev = self.snaps[i-1] if i > 0 else None

        # Render depending on kind
        if snap.kind == "cipher":
            # State grid: show state (highlight vs prev cipher state if available)
            prev_state = prev.state if (prev and prev.kind == "cipher" and prev.state is not None) else None
            self._render_matrix(self.state_cells, snap.state, prev_state)

            # Key grid: show round key
            prev_rk = prev.round_key if (prev and prev.round_key is not None and prev.kind == "cipher") else None
            if snap.round_key is not None:
                self._render_matrix(self.key_cells, snap.round_key, prev_rk)
            else:
                self._clear_grid(self.key_cells)

            # Notes
            more = []
            more.append(f"State (hex): {state_to_hex(snap.state)}")
            if snap.round_key is not None:
                more.append(f"RoundKey{snap.round_idx} (hex): {state_to_hex(snap.round_key)}")
            if snap.note:
                more.append("")
                more.append(snap.note)
            self._set_note("\n".join(more))

        else:
            # KeySchedule step:
            # State grid not used
            self._clear_grid(self.state_cells)

            # show up to 4 key words in key grid
            prev_words = prev.key_words if (prev and prev.kind == "keyschedule") else None
            self._render_words_as_4x4(self.key_cells, snap.key_words[:4], prev_words[:4] if prev_words else None)

            labels = " | ".join([kw["label"] for kw in snap.key_words[:4]]) if snap.key_words else ""
            more = []
            if labels:
                more.append(f"Words shown (columns): {labels}")
            if snap.round_key is not None:
                more.append(f"RoundKey{snap.round_idx} (hex): {state_to_hex(snap.round_key)}")
            if snap.note:
                more.append("")
                more.append(snap.note)

            self._set_note("\n".join(more))

# ----------------------------
# Run
# ----------------------------
if __name__ == "__main__":
    app = AESVisualizerApp()
    app.mainloop()