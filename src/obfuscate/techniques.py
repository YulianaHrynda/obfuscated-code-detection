from __future__ import annotations

import ast
import base64
import marshal
import random
import string
import zlib
from typing import Callable

                                      

def _short_name(rng: random.Random) -> str:
    return "_" + "".join(rng.choices(string.ascii_letters, k=rng.randint(2, 5)))

                                         

class _StringBase64(ast.NodeTransformer):
    """Replace string Constant nodes with base64.b64decode(...).decode()."""

    def __init__(self) -> None:
        self.touched = False

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str) and node.value and len(node.value) >= 2:
                                                                     
                                                                               
            enc = base64.b64encode(node.value.encode("utf-8")).decode("ascii")
            self.touched = True
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(id="base64", ctx=ast.Load()),
                            attr="b64decode",
                            ctx=ast.Load(),
                        ),
                        args=[ast.Constant(value=enc)],
                        keywords=[],
                    ),
                    attr="decode",
                    ctx=ast.Load(),
                ),
                args=[ast.Constant(value="utf-8")],
                keywords=[],
            )
        return node

def base64_strings(src: str) -> str:
    tree = ast.parse(src)
    transformer = _StringBase64()
    new_tree = transformer.visit(tree)
    ast.fix_missing_locations(new_tree)
    if not transformer.touched:
        return src
                                             
    new_tree.body.insert(0, ast.Import(names=[ast.alias(name="base64", asname=None)]))
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree)

                                             

_RESERVED = {
    "self", "cls", "__init__", "__main__", "__name__", "__file__", "__doc__",
    "__class__", "__dict__", "True", "False", "None",
}

class _RenameLocals(ast.NodeTransformer):
    """Rename function parameters + locally-assigned names within each function.

    We do NOT rename module-level imports, class names, or attribute accesses,
    so the script still resolves stdlib calls correctly.
    """

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        return self._rename_function(node)

    def visit_AsyncFunctionDef(self, node):        
        return self._rename_function(node)

    def _rename_function(self, node):
        mapping: dict[str, str] = {}
              
        for arg in node.args.args + node.args.kwonlyargs:
            if arg.arg not in _RESERVED and arg.arg not in mapping:
                mapping[arg.arg] = _short_name(self.rng)
        if node.args.vararg and node.args.vararg.arg not in _RESERVED:
            mapping[node.args.vararg.arg] = _short_name(self.rng)
        if node.args.kwarg and node.args.kwarg.arg not in _RESERVED:
            mapping[node.args.kwarg.arg] = _short_name(self.rng)
                           
        for sub in ast.walk(node):
            if isinstance(sub, ast.Assign):
                for tgt in sub.targets:
                    if isinstance(tgt, ast.Name) and tgt.id not in _RESERVED and tgt.id not in mapping:
                        mapping[tgt.id] = _short_name(self.rng)
            elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                if sub.target.id not in _RESERVED and sub.target.id not in mapping:
                    mapping[sub.target.id] = _short_name(self.rng)
            elif isinstance(sub, ast.For) and isinstance(sub.target, ast.Name):
                if sub.target.id not in _RESERVED and sub.target.id not in mapping:
                    mapping[sub.target.id] = _short_name(self.rng)

                                                                 
        class _Rewrite(ast.NodeTransformer):
            def visit_Name(self, node: ast.Name) -> ast.AST:
                if node.id in mapping:
                    return ast.copy_location(ast.Name(id=mapping[node.id], ctx=node.ctx), node)
                return node

            def visit_arg(self, node: ast.arg) -> ast.AST:
                if node.arg in mapping:
                    return ast.copy_location(ast.arg(arg=mapping[node.arg], annotation=node.annotation), node)
                return node

        node.args = _Rewrite().visit(node.args)
        new_body = []
        for stmt in node.body:
            new_body.append(_Rewrite().visit(stmt))
        node.body = new_body
        return node

def rename_identifiers(src: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random()
    tree = ast.parse(src)
    new_tree = _RenameLocals(rng).visit(tree)
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree)

                                       

def marshal_wrap(src: str) -> str:
    code_obj = compile(src, "<obf>", "exec")
    blob = base64.b64encode(zlib.compress(marshal.dumps(code_obj))).decode("ascii")
    return (
        "import base64, marshal, zlib\n"
        f"_payload = b\"{blob}\"\n"
        "exec(marshal.loads(zlib.decompress(base64.b64decode(_payload))))\n"
    )

                                           

_DEAD_TEMPLATES = [
    "if False:\n    _x = 1\n",
    "_ = [n for n in range(0) if True]\n",
    "_dummy = (lambda: None)()\n",
    "if 1 == 2:\n    raise RuntimeError('unreachable')\n",
    "_noop = sum([])\n",
    "for _ in range(0):\n    pass\n",
]

def dead_code_inject(src: str, rng: random.Random | None = None, density: float = 0.3) -> str:
    rng = rng or random.Random()
    tree = ast.parse(src)
    new_body: list[ast.stmt] = []
    for stmt in tree.body:
        new_body.append(stmt)
        if rng.random() < density:
            dead = ast.parse(rng.choice(_DEAD_TEMPLATES)).body
            new_body.extend(dead)
    tree.body = new_body
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)

                                       

class _StringSplit(ast.NodeTransformer):
    def __init__(self, rng: random.Random, min_len: int = 4) -> None:
        self.rng = rng
        self.min_len = min_len

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not (isinstance(node.value, str) and len(node.value) >= self.min_len):
            return node
        s = node.value
                               
        splits = sorted(self.rng.sample(range(1, len(s)), k=min(self.rng.randint(1, 3), len(s) - 1)))
        parts: list[str] = []
        prev = 0
        for sp in splits:
            parts.append(s[prev:sp])
            prev = sp
        parts.append(s[prev:])
                                        
        result: ast.AST = ast.Constant(value=parts[0])
        for p in parts[1:]:
            result = ast.BinOp(left=result, op=ast.Add(), right=ast.Constant(value=p))
        return result

def string_split(src: str, rng: random.Random | None = None) -> str:
    rng = rng or random.Random()
    tree = ast.parse(src)
    new_tree = _StringSplit(rng).visit(tree)
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree)

                                

TECHNIQUES: dict[str, Callable] = {
    "base64_strings": base64_strings,
    "rename_identifiers": rename_identifiers,
    "marshal_wrap": marshal_wrap,
    "dead_code_inject": dead_code_inject,
    "string_split": string_split,
}

def apply(src: str, technique: str, seed: int | None = None) -> str:
    rng = random.Random(seed) if seed is not None else random.Random()
    fn = TECHNIQUES[technique]
    if technique in ("rename_identifiers", "dead_code_inject", "string_split"):
        return fn(src, rng)
    return fn(src)
