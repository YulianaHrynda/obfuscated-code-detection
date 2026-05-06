from __future__ import annotations

import ast
from dataclasses import dataclass

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer


SHELL_KEYWORDS = ("shell=true", "/bin/sh", "/bin/bash", "cmd.exe", "powershell")


@dataclass
class AstStats:
    num_calls: int
    num_imports: int
    num_strings: int
    num_long_strings: int
    num_exec_eval: int
    num_subprocess: int
    num_socket: int
    num_marshal: int
    num_b64: int
    num_getattr: int
    num_dunder_calls: int
    avg_identifier_len: float
    max_string_len: int
    has_shell_kw: int
    has_install_hook: int
    parses: int

    def to_vec(self) -> np.ndarray:
        return np.array([
            self.num_calls, self.num_imports, self.num_strings,
            self.num_long_strings, self.num_exec_eval, self.num_subprocess,
            self.num_socket, self.num_marshal, self.num_b64, self.num_getattr,
            self.num_dunder_calls, self.avg_identifier_len, self.max_string_len,
            self.has_shell_kw, self.has_install_hook, self.parses,
        ], dtype=np.float32)


def _call_name(call: ast.Call):
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def extract_ast_stats(src: str) -> AstStats:
    has_shell_kw = int(any(kw in src.lower() for kw in SHELL_KEYWORDS))
    has_install_hook = int("cmdclass" in src and "install" in src.lower())

    try:
        tree = ast.parse(src)
        parses = 1
    except (SyntaxError, ValueError):
        return AstStats(
            num_calls=0, num_imports=0, num_strings=0, num_long_strings=0,
            num_exec_eval=0, num_subprocess=0, num_socket=0, num_marshal=0,
            num_b64=0, num_getattr=0, num_dunder_calls=0,
            avg_identifier_len=0.0, max_string_len=0,
            has_shell_kw=has_shell_kw, has_install_hook=has_install_hook,
            parses=0,
        )

    num_calls = num_imports = num_strings = num_long_strings = 0
    num_exec_eval = num_subprocess = num_socket = num_marshal = 0
    num_b64 = num_getattr = num_dunder_calls = 0
    max_str_len = 0
    ident_lens: list[int] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            num_calls += 1
            fname = _call_name(node)
            if fname in ("exec", "eval", "compile"):
                num_exec_eval += 1
            elif fname == "getattr":
                num_getattr += 1
            elif fname and fname.startswith("__") and fname.endswith("__"):
                num_dunder_calls += 1
            if fname and ("b64decode" in fname or "fromhex" in fname):
                num_b64 += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            num_imports += 1
            mod = getattr(node, "module", None)
            names = [a.name for a in node.names] + ([mod] if mod else [])
            for n in names:
                if not n:
                    continue
                low = n.lower()
                if "subprocess" in low:
                    num_subprocess += 1
                if "socket" in low:
                    num_socket += 1
                if "marshal" in low:
                    num_marshal += 1
                if "base64" in low or "codecs" in low:
                    num_b64 += 1
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            num_strings += 1
            sl = len(node.value)
            max_str_len = max(max_str_len, sl)
            if sl > 80:
                num_long_strings += 1
        elif isinstance(node, ast.Name):
            ident_lens.append(len(node.id))
        elif isinstance(node, ast.FunctionDef):
            ident_lens.append(len(node.name))

    avg_id_len = float(np.mean(ident_lens)) if ident_lens else 0.0

    return AstStats(
        num_calls=num_calls, num_imports=num_imports, num_strings=num_strings,
        num_long_strings=num_long_strings, num_exec_eval=num_exec_eval,
        num_subprocess=num_subprocess, num_socket=num_socket,
        num_marshal=num_marshal, num_b64=num_b64, num_getattr=num_getattr,
        num_dunder_calls=num_dunder_calls, avg_identifier_len=avg_id_len,
        max_string_len=max_str_len, has_shell_kw=has_shell_kw,
        has_install_hook=has_install_hook, parses=parses,
    )


class HybridVectorizer:
    def __init__(self):
        self.word_vec = TfidfVectorizer(
            analyzer="word", ngram_range=(1, 2),
            max_features=20000, sublinear_tf=True, min_df=2,
        )
        self.char_vec = TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5),
            max_features=30000, sublinear_tf=True, min_df=2,
        )

    def fit_transform(self, texts: list[str]):
        word_x = self.word_vec.fit_transform(texts)
        char_x = self.char_vec.fit_transform(texts)
        ast_x = self._ast_block(texts)
        return sparse.hstack([word_x, char_x, ast_x], format="csr")

    def transform(self, texts: list[str]):
        word_x = self.word_vec.transform(texts)
        char_x = self.char_vec.transform(texts)
        ast_x = self._ast_block(texts)
        return sparse.hstack([word_x, char_x, ast_x], format="csr")

    @staticmethod
    def _ast_block(texts: list[str]):
        rows = [extract_ast_stats(t).to_vec() for t in texts]
        return sparse.csr_matrix(np.vstack(rows))
