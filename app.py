import os
import sys
import threading
import datetime
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, filedialog


APP_TITEL_DE = "PGP Schlüssel-Manager"
APP_TITEL_EN = "PGP Key-Manager"
APP_VERSION = "1.0.0"
APP_AUTHOR = "©BYLICKILABS | ©Thorsten Bylicki"
APP_DESCRIPTION_DE = (
    "Erzeugt moderne OpenPGP-Schlüsselpaare (RSA/Ed25519), schützt den privaten Schlüssel mit "
    "Passphrase, verwaltet Nutzungsflags, zeigt Fingerprint & Metadaten und erlaubt Speichern/Kopieren "
    "der ASCII-gepanzerten Schlüssel."
)
APP_DESCRIPTION_EN = (
    "Generates modern OpenPGP keypairs (RSA/Ed25519), protects the private key with a passphrase, "
    "manages usage flags, shows fingerprint & metadata, and allows saving/copying the ASCII-armored keys."
)

PGPY_AVAILABLE = True
PGPY_IMPORT_ERROR = None
try:
    from pgpy import PGPKey, PGPUID
    from pgpy.constants import (
        PubKeyAlgorithm,
        KeyFlags,
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
        EllipticCurveOID,
    )
except Exception as e:
    PGPY_AVAILABLE = False
    PGPY_IMPORT_ERROR = e

GITHUB_URL = "https://github.com/bylickilabs"

def _resource_path(*parts: str) -> str:
    """
    Liefert Pfade sowohl im Dev-Run als auch im PyInstaller-Bundle.
    """
    base = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base, *parts)

def _try_set_icon(root: tk.Tk):
    ico_path = _resource_path("assets", "icon.ico")
    if os.path.exists(ico_path):
        try:
            root.iconbitmap(ico_path)
        except Exception:
            pass

TEXTS = {
    "en": {
        "window_title": f"{APP_TITEL_EN} v{APP_VERSION} — {APP_AUTHOR}",
        "section_input": "Identity & Options",
        "name": "Name",
        "email": "Email",
        "comment": "Comment (optional)",
        "passphrase": "Passphrase",
        "confirm_pass": "Confirm Passphrase",
        "algo": "Algorithm",
        "rsa_2048": "RSA 2048",
        "rsa_3072": "RSA 3072",
        "rsa_4096": "RSA 4096",
        "eddsa_25519": "Ed25519 (if supported)",
        "expires_days": "Expiration (days, 0 = no expiry)",
        "usage": "Key Usage",
        "usage_sign": "Sign",
        "usage_encrypt": "Encrypt",
        "usage_storage": "Encrypt Storage",
        "usage_certify": "Certify",
        "usage_auth": "Authenticate",
        "actions": "Actions",
        "btn_generate": "Generate Key",
        "btn_clear": "Clear",
        "btn_save_pub": "Save Public Key",
        "btn_save_priv": "Save Private Key",
        "btn_copy_pub": "Copy Public",
        "btn_copy_priv": "Copy Private",
        "btn_github": "GitHub",
        "btn_info": "Info",
        "lang_toggle": "DE/EN",
        "section_output": "Key Details",
        "fingerprint": "Fingerprint",
        "keyid": "Key ID",
        "algorithm": "Algorithm",
        "bits": "Bits",
        "created": "Created",
        "expires": "Expires",
        "public_key": "Public Key (ASCII-armored)",
        "private_key": "Private Key (ASCII-armored)",
        "status_ready": "Ready.",
        "status_generating": "Generating key… This may take a moment.",
        "status_done": "Key generated successfully.",
        "status_saved_pub": "Public key saved.",
        "status_saved_priv": "Private key saved.",
        "err_missing_pgpy": "The 'pgpy' package could not be imported. Please install it: pip install pgpy",
        "err_inputs": "Please enter Name, a valid Email, and matching Passphrases.",
        "err_email": "Please provide a valid email address.",
        "err_pass_match": "Passphrases do not match.",
        "err_no_key": "No key in memory. Generate a key first.",
        "err_save": "Could not save the file.",
        "dlg_pub_save": "Save Public Key",
        "dlg_priv_save": "Save Private Key",
        "info_title": "About – PGP Key Manager",
        "ok": "OK",
        "confirm_clear_title": "Clear",
        "confirm_clear_msg": "Remove generated keys and reset the form?",
        "msg_copied": "Copied to clipboard.",
        "info_body": (
            f"{APP_TITEL_EN} v{APP_VERSION} — {APP_AUTHOR}\n\n"
            f"{APP_DESCRIPTION_EN}\n\n"
            "Workflow:\n"
            "1) Enter name, email and optional comment.\n"
            "2) Choose algorithm and expiry.\n"
            "3) Select key usage flags.\n"
            "4) Provide a strong passphrase and confirm it.\n"
            "5) Click 'Generate Key'.\n\n"
            "Results:\n"
            "• Fingerprint and meta details are shown.\n"
            "• Public and private keys (ASCII-armored) are displayed.\n"
            "• Save keys to files and/or copy to clipboard.\n\n"
            "Security Notice:\n"
            "Your private key is only kept in memory until you clear or close the app.\n"
            "Dependencies: PGPy, cryptography."
        ),
    },
    "de": {
        "window_title": f"{APP_TITEL_DE} v{APP_VERSION} — {APP_AUTHOR}",
        "section_input": "Identität & Optionen",
        "name": "Name",
        "email": "E-Mail",
        "comment": "Kommentar (optional)",
        "passphrase": "Passphrase",
        "confirm_pass": "Passphrase bestätigen",
        "algo": "Algorithmus",
        "rsa_2048": "RSA 2048",
        "rsa_3072": "RSA 3072",
        "rsa_4096": "RSA 4096",
        "eddsa_25519": "Ed25519 (falls unterstützt)",
        "expires_days": "Ablauf (Tage, 0 = kein Ablauf)",
        "usage": "Schlüsselverwendung",
        "usage_sign": "Signieren",
        "usage_encrypt": "Verschlüsseln",
        "usage_storage": "Speicher verschl.",
        "usage_certify": "Zertifizieren",
        "usage_auth": "Authentifizieren",
        "actions": "Aktionen",
        "btn_generate": "Schlüssel erzeugen",
        "btn_clear": "Zurücksetzen",
        "btn_save_pub": "Öffentlichen Schlüssel speichern",
        "btn_save_priv": "Privaten Schlüssel speichern",
        "btn_copy_pub": "Öffentlichen kopieren",
        "btn_copy_priv": "Privaten kopieren",
        "btn_github": "GitHub",
        "btn_info": "Info",
        "lang_toggle": "DE/EN",
        "section_output": "Schlüsseldetails",
        "fingerprint": "Fingerprint",
        "keyid": "Schlüssel-ID",
        "algorithm": "Algorithmus",
        "bits": "Bits",
        "created": "Erstellt",
        "expires": "Läuft ab",
        "public_key": "Öffentlicher Schlüssel (ASCII-gepanzert)",
        "private_key": "Privater Schlüssel (ASCII-gepanzert)",
        "status_ready": "Bereit.",
        "status_generating": "Schlüssel wird erzeugt… Das kann einen Moment dauern.",
        "status_done": "Schlüssel erfolgreich erzeugt.",
        "status_saved_pub": "Öffentlicher Schlüssel gespeichert.",
        "status_saved_priv": "Privater Schlüssel gespeichert.",
        "err_missing_pgpy": "Das Paket 'pgpy' konnte nicht importiert werden. Bitte installieren: pip install pgpy",
        "err_inputs": "Bitte Name, gültige E-Mail und identische Passphrasen eingeben.",
        "err_email": "Bitte eine gültige E-Mail-Adresse angeben.",
        "err_pass_match": "Passphrasen stimmen nicht überein.",
        "err_no_key": "Kein Schlüssel im Speicher. Bitte zuerst erzeugen.",
        "err_save": "Datei konnte nicht gespeichert werden.",
        "dlg_pub_save": "Öffentlichen Schlüssel speichern",
        "dlg_priv_save": "Privaten Schlüssel speichern",
        "info_title": "Über – PGP Schlüssel-Manager",
        "ok": "OK",
        "confirm_clear_title": "Zurücksetzen",
        "confirm_clear_msg": "Erzeugte Schlüssel entfernen und Formular zurücksetzen?",
        "msg_copied": "In die Zwischenablage kopiert.",
        "info_body": (
            f"{APP_TITEL_DE} v{APP_VERSION} — {APP_AUTHOR}\n\n"
            f"{APP_DESCRIPTION_DE}\n\n"
            "Ablauf:\n"
            "1) Name, E-Mail und optionalen Kommentar eingeben.\n"
            "2) Algorithmus und Ablauf festlegen.\n"
            "3) Nutzungsflags auswählen.\n"
            "4) Starke Passphrase eingeben und bestätigen.\n"
            "5) Auf 'Schlüssel erzeugen' klicken.\n\n"
            "Ergebnis:\n"
            "• Fingerprint und Metadaten werden angezeigt.\n"
            "• Öffentlicher und privater Schlüssel (ASCII-gepanzert) werden dargestellt.\n"
            "• Schlüssel können gespeichert oder in die Zwischenablage kopiert werden.\n\n"
            "Sicherheitshinweis:\n"
            "Ihr privater Schlüssel verbleibt nur im Speicher, bis Sie die App schließen oder zurücksetzen.\n"
            "Abhängigkeiten: PGPy, cryptography."
        ),
    },
}


class PGPKeyManagerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.lang = "de"
        self.t = TEXTS[self.lang]

        self._privkey: str | None = None
        self._pubkey: str | None = None

        self._build_ui()
        _try_set_icon(self.root)
        self._apply_i18n()
        self._set_status(self.t["status_ready"])

    def _build_ui(self):
        self.root.title(self.t["window_title"])
        self.root.geometry("1366x860")
        self.root.minsize(1240, 780)

        self.main = ttk.Frame(self.root, padding=12)
        self.main.pack(fill=tk.BOTH, expand=True)

        self.main.columnconfigure(0, weight=0)
        self.main.columnconfigure(1, weight=1)
        self.main.rowconfigure(0, weight=1)
        self.main.rowconfigure(1, weight=0)

        self.left = ttk.LabelFrame(self.main, text="")
        self.left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        for i in range(0, 20):
            self.left.rowconfigure(i, weight=0)
        self.left.columnconfigure(0, weight=0, minsize=200)
        self.left.columnconfigure(1, weight=1)

        self.lbl_name = ttk.Label(self.left, text="Name")
        self.ent_name = ttk.Entry(self.left)

        self.lbl_email = ttk.Label(self.left, text="Email")
        self.ent_email = ttk.Entry(self.left)

        self.lbl_comment = ttk.Label(self.left, text="Comment (optional)")
        self.ent_comment = ttk.Entry(self.left)

        self.lbl_pass = ttk.Label(self.left, text="Passphrase")
        self.ent_pass = ttk.Entry(self.left, show="•")

        self.lbl_pass2 = ttk.Label(self.left, text="Confirm Passphrase")
        self.ent_pass2 = ttk.Entry(self.left, show="•")

        self.lbl_algo = ttk.Label(self.left, text="Algorithm")
        self.cbo_algo = ttk.Combobox(self.left, state="readonly",
                                     values=["RSA 2048", "RSA 3072", "RSA 4096", "Ed25519"])
        self.cbo_algo.current(2)

        self.lbl_exp = ttk.Label(self.left, text="Expiration (days)")
        self.spn_exp = ttk.Spinbox(self.left, from_=0, to=3650, increment=1, width=12)
        self.spn_exp.set("0")

        self.frm_usage = ttk.Labelframe(self.left, text="Usage")
        self.var_sign = tk.BooleanVar(value=True)
        self.var_encrypt = tk.BooleanVar(value=True)
        self.var_storage = tk.BooleanVar(value=True)
        self.var_certify = tk.BooleanVar(value=True)
        self.var_auth = tk.BooleanVar(value=False)
        self.chk_sign = ttk.Checkbutton(self.frm_usage, variable=self.var_sign, text="Sign")
        self.chk_encrypt = ttk.Checkbutton(self.frm_usage, variable=self.var_encrypt, text="Encrypt")
        self.chk_storage = ttk.Checkbutton(self.frm_usage, variable=self.var_storage, text="Encrypt Storage")
        self.chk_certify = ttk.Checkbutton(self.frm_usage, variable=self.var_certify, text="Certify")
        self.chk_auth = ttk.Checkbutton(self.frm_usage, variable=self.var_auth, text="Authenticate")

        self.frm_actions = ttk.Labelframe(self.left, text="Actions")
        self.btn_generate = ttk.Button(self.frm_actions, text="Generate", command=self.on_generate)
        self.btn_clear = ttk.Button(self.frm_actions, text="Clear", command=self.on_clear)
        self.btn_github = ttk.Button(self.frm_actions, text="GitHub",
                                     command=lambda: webbrowser.open(GITHUB_URL))
        self.btn_info = ttk.Button(self.frm_actions, text="Info", command=self.on_info)
        self.btn_lang = ttk.Button(self.frm_actions, text="DE/EN", command=self.on_toggle_lang)

        r = 0
        ttk.Label(self.left, text=self.t["section_input"], style="Header.TLabel")\
            .grid(row=r, column=0, columnspan=2, sticky="w", pady=(8, 8))
        r += 1
        self.lbl_name.grid(row=r, column=0, sticky="w", padx=8, pady=4)
        self.ent_name.grid(row=r, column=1, sticky="ew", padx=8, pady=4)
        r += 1
        self.lbl_email.grid(row=r, column=0, sticky="w", padx=8, pady=4)
        self.ent_email.grid(row=r, column=1, sticky="ew", padx=8, pady=4)
        r += 1
        self.lbl_comment.grid(row=r, column=0, sticky="w", padx=8, pady=4)
        self.ent_comment.grid(row=r, column=1, sticky="ew", padx=8, pady=4)
        r += 1
        self.lbl_pass.grid(row=r, column=0, sticky="w", padx=8, pady=4)
        self.ent_pass.grid(row=r, column=1, sticky="ew", padx=8, pady=4)
        r += 1
        self.lbl_pass2.grid(row=r, column=0, sticky="w", padx=8, pady=4)
        self.ent_pass2.grid(row=r, column=1, sticky="ew", padx=8, pady=4)
        r += 1
        self.lbl_algo.grid(row=r, column=0, sticky="w", padx=8, pady=4)
        self.cbo_algo.grid(row=r, column=1, sticky="ew", padx=8, pady=4)
        r += 1
        self.lbl_exp.grid(row=r, column=0, sticky="w", padx=8, pady=4)
        self.spn_exp.grid(row=r, column=1, sticky="w", padx=8, pady=4)
        r += 1
        self.frm_usage.grid(row=r, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 8))
        for i, w in enumerate([self.chk_sign, self.chk_encrypt, self.chk_storage, self.chk_certify, self.chk_auth]):
            w.grid(row=0, column=i, sticky="w", padx=8, pady=4)
        r += 1
        self.frm_actions.grid(row=r, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 8))
        for c in range(5):
            self.frm_actions.columnconfigure(c, weight=(1 if c == 4 else 0))
        self.btn_generate.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.btn_clear.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        self.btn_github.grid(row=0, column=2, padx=10, pady=10, sticky="w")
        self.btn_info.grid(row=0, column=3, padx=10, pady=10, sticky="w")
        self.btn_lang.grid(row=0, column=4, padx=10, pady=10, sticky="e")

        r += 1
        self.progress = ttk.Progressbar(self.left, mode="indeterminate")
        self.progress.grid(row=r, column=0, columnspan=2, sticky="ew", padx=8, pady=(4, 8))

        self.right = ttk.LabelFrame(self.main, text="")
        self.right.grid(row=0, column=1, sticky="nsew")
        self.main.rowconfigure(0, weight=1)
        self.right.columnconfigure(0, weight=0)
        self.right.columnconfigure(1, weight=1)
        self.right.columnconfigure(2, weight=0)
        for i in range(0, 12):
            self.right.rowconfigure(i, weight=0)
        self.right.rowconfigure(6, weight=1)
        self.right.rowconfigure(8, weight=1)

        ttk.Label(self.right, text=self.t["section_output"], style="Header.TLabel")\
            .grid(row=0, column=0, columnspan=3, sticky="w", padx=8, pady=8)

        self.lbl_fp = ttk.Label(self.right, text="Fingerprint:")
        self.val_fp = ttk.Entry(self.right, state="readonly")
        self.lbl_kid = ttk.Label(self.right, text="Key ID:")
        self.val_kid = ttk.Entry(self.right, state="readonly")
        self.lbl_alg = ttk.Label(self.right, text="Algorithm:")
        self.val_alg = ttk.Entry(self.right, state="readonly")
        self.lbl_bits = ttk.Label(self.right, text="Bits:")
        self.val_bits = ttk.Entry(self.right, state="readonly")
        self.lbl_created = ttk.Label(self.right, text="Created:")
        self.val_created = ttk.Entry(self.right, state="readonly")
        self.lbl_expires = ttk.Label(self.right, text="Expires:")
        self.val_expires = ttk.Entry(self.right, state="readonly")

        r2 = 1
        self.lbl_fp.grid(row=r2, column=0, sticky="w", padx=8, pady=4)
        self.val_fp.grid(row=r2, column=1, columnspan=2, sticky="ew", padx=8, pady=4)
        r2 += 1
        self.lbl_kid.grid(row=r2, column=0, sticky="w", padx=8, pady=4)
        self.val_kid.grid(row=r2, column=1, columnspan=2, sticky="ew", padx=8, pady=4)
        r2 += 1
        self.lbl_alg.grid(row=r2, column=0, sticky="w", padx=8, pady=4)
        self.val_alg.grid(row=r2, column=1, sticky="ew", padx=8, pady=4)
        self.lbl_bits.grid(row=r2, column=2, sticky="w", padx=8, pady=4)
        r2 += 1
        self.lbl_created.grid(row=r2, column=0, sticky="w", padx=8, pady=4)
        self.val_created.grid(row=r2, column=1, sticky="ew", padx=8, pady=4)
        self.lbl_expires.grid(row=r2, column=2, sticky="w", padx=8, pady=4)

        r2 += 1
        self.lbl_pub = ttk.Label(self.right, text="Public Key")
        self.btn_copy_pub = ttk.Button(self.right, text="Copy Public", command=self.copy_public)
        self.btn_save_pub = ttk.Button(self.right, text="Save Public Key", command=self.save_public)
        self.txt_pub = tk.Text(self.right, wrap="none", height=12)
        self.scr_pub_y = ttk.Scrollbar(self.right, orient="vertical", command=self.txt_pub.yview)
        self.txt_pub.configure(yscrollcommand=self.scr_pub_y.set)

        self.lbl_pub.grid(row=r2, column=0, sticky="w", padx=8, pady=(8, 4))
        self.btn_copy_pub.grid(row=r2, column=1, sticky="e", padx=8, pady=(8, 4))
        self.btn_save_pub.grid(row=r2, column=2, sticky="e", padx=8, pady=(8, 4))
        r2 += 1
        self.txt_pub.grid(row=r2, column=0, columnspan=3, sticky="nsew", padx=(8, 0), pady=(0, 8))
        self.scr_pub_y.grid(row=r2, column=3, sticky="ns", pady=(0, 8))

        r2 += 1
        self.lbl_priv = ttk.Label(self.right, text="Private Key")
        self.btn_copy_priv = ttk.Button(self.right, text="Copy Private", command=self.copy_private)
        self.btn_save_priv = ttk.Button(self.right, text="Save Private Key", command=self.save_private)
        self.txt_priv = tk.Text(self.right, wrap="none", height=12)
        self.scr_priv_y = ttk.Scrollbar(self.right, orient="vertical", command=self.txt_priv.yview)
        self.txt_priv.configure(yscrollcommand=self.scr_priv_y.set)

        self.lbl_priv.grid(row=r2, column=0, sticky="w", padx=8, pady=(8, 4))
        self.btn_copy_priv.grid(row=r2, column=1, sticky="e", padx=8, pady=(8, 4))
        self.btn_save_priv.grid(row=r2, column=2, sticky="e", padx=8, pady=(8, 4))
        r2 += 1
        self.txt_priv.grid(row=r2, column=0, columnspan=3, sticky="nsew", padx=(8, 0), pady=(0, 8))
        self.scr_priv_y.grid(row=r2, column=3, sticky="ns", pady=(0, 8))

        self.status = ttk.Label(self.main, text="", anchor="w")
        self.status.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))

        style = ttk.Style(self.root)
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"))

    def _apply_i18n(self):
        self.t = TEXTS[self.lang]
        self.root.title(self.t["window_title"])
        self.left.configure(text=self.t["section_input"])
        self.lbl_name.configure(text=self.t["name"])
        self.lbl_email.configure(text=self.t["email"])
        self.lbl_comment.configure(text=self.t["comment"])
        self.lbl_pass.configure(text=self.t["passphrase"])
        self.lbl_pass2.configure(text=self.t["confirm_pass"])
        self.lbl_algo.configure(text=self.t["algo"])
        self.lbl_exp.configure(text=self.t["expires_days"])
        self.frm_usage.configure(text=self.t["usage"])
        self.chk_sign.configure(text=self.t["usage_sign"])
        self.chk_encrypt.configure(text=self.t["usage_encrypt"])
        self.chk_storage.configure(text=self.t["usage_storage"])
        self.chk_certify.configure(text=self.t["usage_certify"])
        self.chk_auth.configure(text=self.t["usage_auth"])
        self.frm_actions.configure(text=self.t["actions"])
        self.btn_generate.configure(text=self.t["btn_generate"])
        self.btn_clear.configure(text=self.t["btn_clear"])
        self.btn_github.configure(text=self.t["btn_github"])
        self.btn_info.configure(text=self.t["btn_info"])
        self.btn_lang.configure(text=self.t["lang_toggle"])
        self.right.configure(text=self.t["section_output"])
        self.lbl_fp.configure(text=f"{self.t['fingerprint']}:")
        self.lbl_kid.configure(text=f"{self.t['keyid']}:")
        self.lbl_alg.configure(text=f"{self.t['algorithm']}:")
        self.lbl_bits.configure(text=f"{self.t['bits']}:")
        self.lbl_created.configure(text=f"{self.t['created']}:")
        self.lbl_expires.configure(text=f"{self.t['expires']}:")
        self.lbl_pub.configure(text=self.t["public_key"])
        self.btn_copy_pub.configure(text=self.t["btn_copy_pub"])
        self.btn_save_pub.configure(text=self.t["btn_save_pub"])
        self.lbl_priv.configure(text=self.t["private_key"])
        self.btn_copy_priv.configure(text=self.t["btn_copy_priv"])
        self.btn_save_priv.configure(text=self.t["btn_save_priv"])

    def _set_status(self, text: str):
        self.status.configure(text=text)

    def on_toggle_lang(self):
        self.lang = "en" if self.lang == "de" else "de"
        self._apply_i18n()
        self._set_status(self.t["status_ready"])

    def on_info(self):
        info = tk.Toplevel(self.root)
        info.title(self.t["info_title"])
        info.geometry("860x620")
        info.transient(self.root)
        info.grab_set()

        txt = tk.Text(info, wrap="word")
        txt.insert("1.0", self.t["info_body"])
        txt.configure(state="disabled")
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        ttk.Button(info, text=self.t["ok"], command=info.destroy).pack(pady=(0, 12))

    def on_clear(self):
        if messagebox.askyesno(self.t["confirm_clear_title"], self.t["confirm_clear_msg"]):
            for e in (self.ent_name, self.ent_email, self.ent_comment, self.ent_pass, self.ent_pass2):
                e.delete(0, tk.END)
            self.cbo_algo.current(2)
            self.spn_exp.set("0")
            for v in (self.var_sign, self.var_encrypt, self.var_storage, self.var_certify, self.var_auth):
                v.set(False)
            self.var_sign.set(True)
            self.var_encrypt.set(True)
            self.var_storage.set(True)
            self.var_certify.set(True)
            self.txt_pub.delete("1.0", tk.END)
            self.txt_priv.delete("1.0", tk.END)
            self._privkey = None
            self._pubkey = None

            for w in (self.val_fp, self.val_kid, self.val_alg, self.val_bits, self.val_created, self.val_expires):
                w.configure(state="normal")
                w.delete(0, tk.END)
                w.configure(state="readonly")

            self._set_status(self.t["status_ready"])

    def _validate_inputs(self):
        import re
        name = self.ent_name.get().strip()
        email = self.ent_email.get().strip()
        pass1 = self.ent_pass.get()
        pass2 = self.ent_pass2.get()
        if not name or not email or not pass1 or not pass2:
            return False, self.t["err_inputs"]
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            return False, self.t["err_email"]
        if pass1 != pass2:
            return False, self.t["err_pass_match"]
        return True, ""

    def on_generate(self):
        if not PGPY_AVAILABLE:
            message = f"{self.t['err_missing_pgpy']}"
            if PGPY_IMPORT_ERROR:
                message += f"\n\nDetails: {PGPY_IMPORT_ERROR}"
            messagebox.showerror(self.t["window_title"], message)
            return

        ok, err = self._validate_inputs()
        if not ok:
            messagebox.showerror(self.t["window_title"], err)
            return

        self._set_status(self.t["status_generating"])
        self.progress.start(10)
        self.btn_generate.configure(state="disabled")
        t = threading.Thread(target=self._generate_key_thread, daemon=True)
        t.start()

    def _collect_usage_flags(self):
        flags = set()
        if self.var_sign.get():
            flags.add(KeyFlags.Sign)
        if self.var_encrypt.get():
            flags.add(KeyFlags.EncryptCommunications)
        if self.var_storage.get():
            flags.add(KeyFlags.EncryptStorage)
        if self.var_certify.get():
            flags.add(KeyFlags.Certify)
        if self.var_auth.get():
            flags.add(KeyFlags.Authentication)
        if not flags:
            flags = {KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage, KeyFlags.Certify}
        return flags

    def _generate_key_thread(self):
        try:
            name = self.ent_name.get().strip()
            email = self.ent_email.get().strip()
            comment = self.ent_comment.get().strip()
            passphrase = self.ent_pass.get()
            algo_label = self.cbo_algo.get()
            days = int(self.spn_exp.get()) if self.spn_exp.get() else 0
            key_expires = datetime.timedelta(days=days) if days > 0 else None
            usage = self._collect_usage_flags()

            uid = PGPUID.new(name, email, comment if comment else None)

            selected_bits = None
            if algo_label.startswith("RSA"):
                selected_bits = int(algo_label.split()[1])
                key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, selected_bits)
            else:
                try:
                    key = PGPKey.new(PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519)
                except Exception:
                    selected_bits = 4096
                    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, selected_bits)

            key.add_uid(
                uid,
                usage=usage,
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                compression=[
                    CompressionAlgorithm.ZLIB,
                    CompressionAlgorithm.BZ2,
                    CompressionAlgorithm.ZIP,
                    CompressionAlgorithm.Uncompressed,
                ],
                key_expires=key_expires,
            )

            key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

            pubkey = key.pubkey
            priv_armored = str(key)
            pub_armored = str(pubkey)

            bits_val = getattr(key, "key_size", None)
            if getattr(key, "key_algorithm", None) == PubKeyAlgorithm.EdDSA:
                bits_val = 25519
            if bits_val is None and selected_bits is not None:
                bits_val = selected_bits

            key_id_val = getattr(key, "keyid", None) or getattr(key, "key_id", None)

            meta = {
                "fingerprint": key.fingerprint,
                "keyid": key_id_val,
                "algorithm": str(key.key_algorithm),
                "bits": bits_val if bits_val is not None else "-",
                "created": key.created,
                "expires": getattr(key, "expires_at", None),
                "priv": priv_armored,
                "pub": pub_armored,
            }
        except Exception as e:
            meta = {"error": e}

        self.root.after(0, self._on_generated_done, meta)

    def _on_generated_done(self, meta: dict):
        self.progress.stop()
        self.btn_generate.configure(state="normal")
        if "error" in meta:
            messagebox.showerror(self.t["window_title"], str(meta["error"]))
            self._set_status(self.t["status_ready"])
            return

        self._privkey = meta["priv"]
        self._pubkey = meta["pub"]

        def set_entry(entry: ttk.Entry, val: str):
            entry.configure(state="normal")
            entry.delete(0, tk.END)
            entry.insert(0, val if val is not None else "-")
            entry.configure(state="readonly")

        set_entry(self.val_fp, meta.get("fingerprint", "-"))
        set_entry(self.val_kid, str(meta.get("keyid", "-")))
        set_entry(self.val_alg, meta.get("algorithm", "-"))
        set_entry(self.val_bits, str(meta.get("bits", "-")))
        created = meta.get("created")
        expires = meta.get("expires")
        set_entry(self.val_created, created.isoformat() if created else "-")
        set_entry(self.val_expires, "-" if not expires else expires.isoformat())

        self.txt_pub.delete("1.0", tk.END)
        self.txt_pub.insert("1.0", self._pubkey)
        self.txt_priv.delete("1.0", tk.END)
        self.txt_priv.insert("1.0", self._privkey)

        self._set_status(self.t["status_done"])

    def copy_public(self):
        if not self._pubkey:
            messagebox.showwarning(self.t["window_title"], self.t["err_no_key"])
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self._pubkey)
        self._set_status(self.t["msg_copied"])

    def copy_private(self):
        if not self._privkey:
            messagebox.showwarning(self.t["window_title"], self.t["err_no_key"])
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self._privkey)
        self._set_status(self.t["msg_copied"])

    def save_public(self):
        if not self._pubkey:
            messagebox.showwarning(self.t["window_title"], self.t["err_no_key"])
            return
        path = filedialog.asksaveasfilename(
            title=self.t["dlg_pub_save"],
            defaultextension=".asc",
            filetypes=(("ASCII Armor", "*.asc"), ("Text", "*.txt"), ("All Files", "*.*")),
            initialfile="public.asc",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._pubkey)
            self._set_status(self.t["status_saved_pub"])
        except Exception:
            messagebox.showerror(self.t["window_title"], self.t["err_save"])

    def save_private(self):
        if not self._privkey:
            messagebox.showwarning(self.t["window_title"], self.t["err_no_key"])
            return
        path = filedialog.asksaveasfilename(
            title=self.t["dlg_priv_save"],
            defaultextension=".asc",
            filetypes=(("ASCII Armor", "*.asc"), ("Text", "*.txt"), ("All Files", "*.*")),
            initialfile="private.asc",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._privkey)
            self._set_status(self.t["status_saved_priv"])
        except Exception:
            messagebox.showerror(self.t["window_title"], self.t["err_save"])


if __name__ == "__main__":
    root = tk.Tk()
    app = PGPKeyManagerApp(root)
    root.mainloop()
