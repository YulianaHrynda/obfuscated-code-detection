# obfuscated-code-detection

Бінарний класифікатор `benign / malicious-like` для Python-скриптів зі стрес-тестом
на обфускацію та adversarial fine-tuning. Усе працює локально, на CPU, без
GPU/трансформерів.

## Pipeline

| Етап | Скрипт | Що робить |
|---|---|---|
| 1. Research | `docs/01_obfuscation_techniques.md` | Огляд методів обфускації Python (base64, marshal, rename, dead-code, AST flatten…) |
| 2a. Benign synth | `src/collect/benign_generator.py` | 1500 синтетичних benign-скриптів (CSV/JSON/HTTP/file IO/logging…) — 20 темплейтів |
| 2b. Benign ambiguous | `src/collect/benign_ambiguous.py` | 800 DevOps-скриптів, що легально використовують subprocess/socket/requests (kubectl, docker, rsync, slack-webhook, prometheus…) |
| 2c. Benign real | `src/collect/benign_real.py` | 1500 реальних benign-файлів зі stdlib + site-packages (з природним overlap-вокабуляром) |
| 2d. Malicious synth | `src/collect/malicious_generator.py` | 1500 синтетичних malicious-like (subprocess shell=True, reverse shell, exec/eval, exfil…) |
| 2e. Malicious real | `src/collect/datadog_extract.py` | 800 реальних `setup.py`/`__init__.py` з [DataDog malicious-software-packages](https://github.com/DataDog/malicious-software-packages-dataset) |
| 2f. Splits | `src/collect/build_splits.py` | Stratified 80/10/10 + tag obfuscated source split |
| 3. Obfuscate | `src/obfuscate/apply_all.py` | 5 технік до всіх 6100 скриптів → ~30 500 артефактів |
| 4. Baseline | `src/models/baseline.py` | TF-IDF (word + char) + AST features + LogReg на чистих даних |
| 5. Drift test | `src/eval/drift_test.py` | Baseline на обфускованих held-out скриптах |
| 6. Augmented | `src/models/augmented.py` | Re-train на clean + obfuscated, before/after comparison |

## Як запустити end-to-end

```bash
pip install scikit-learn xgboost seaborn

# 1. Дані
python3 src/collect/benign_generator.py
python3 src/collect/benign_ambiguous.py
python3 src/collect/benign_real.py
python3 src/collect/malicious_generator.py

# 2. Реальні DataDog семпли (опційно але рекомендовано)
git clone --filter=blob:none --no-checkout --depth=1 \
    https://github.com/DataDog/malicious-software-packages-dataset.git \
    /tmp/datadog-malware
cd /tmp/datadog-malware && git sparse-checkout init --cone \
    && git sparse-checkout set samples/pypi && git checkout && cd -
python3 src/collect/datadog_extract.py

# 3. Splits + обфускація
python3 src/collect/build_splits.py
python3 src/obfuscate/apply_all.py
python3 src/collect/build_splits.py

# 4-6. Моделі
python3 src/models/baseline.py
python3 src/eval/drift_test.py
python3 src/models/augmented.py

# Бонус: повний ноутбук + PDF звіт
jupyter nbconvert --to notebook --execute notebooks/obfuscated_code_detection.ipynb \
    --output obfuscated_code_detection.ipynb
python3 src/eval/render_pdf.py
```

## Результати

Тренувальний пул: 3040 benign (1200 synth + 640 ambiguous + 1200 real stdlib) + 1840 malicious (1200 synth + 640 real DataDog).
Held-out test: 610. Обфускованих артефактів: ~30 500 (5 технік × 6100 джерел, мінус skip через f-strings).

### Чистий baseline

| Split | Acc | Precision | Recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| `clean_test` (610) | **0.990** | 0.996 | 0.978 | 0.987 | 0.999 |
| `synth_eval` (synth malware vs benign) | 0.998 | 0.993 | 1.000 | 0.997 | 1.000 |
| `real_eval` (DataDog vs benign) | 0.987 | 0.987 | **0.939** | 0.962 | 0.999 |
| `hard_eval` (DataDog vs ambiguous benign) | **0.968** | 1.000 | 0.939 | 0.969 | 1.000 |

> Метрики тепер реалістичні: модель пропускає ~6% реального malware і має F1 0.97 на найжорсткішій підмножині (real malware × DevOps benign).

### Drift на обфускованих (baseline trained on clean only)

| Технік | Acc | Recall | F1 | Per-class drift |
|---|---:|---:|---:|---|
| `dead_code_inject` | 0.987 | 0.974 | 0.982 | мінімальний |
| `rename_identifiers` | 0.989 | 0.983 | 0.985 | мінімальний |
| `string_split` | 0.987 | 0.978 | 0.983 | мінімальний |
| `base64_strings` | **0.398** | 1.000 | 0.556 | benign-обфусковані: 3% правильно (97% false-positive) |
| `marshal_wrap` | **0.377** | 1.000 | 0.548 | benign-обфусковані: 0% правильно |
| **all (3050)** | **0.748** | 0.987 | 0.747 | — |

Baseline вивчив очевидну, але крихку асоціацію: `base64`/`marshal` ≈ malicious. Коли benign-скрипт обгортають тими ж патернами, модель помилково класифікує його як malicious — точність падає нижче рівня випадкового вибору.

### Augmented (re-trained on clean + obfuscated)

| Метрика | Baseline | Augmented | Δ |
|---|---:|---:|---:|
| obfuscated (all), Acc | 0.748 | **0.968** | **+0.220** |
| obfuscated (all), F1 | 0.747 | **0.957** | **+0.210** |
| obfuscated (all), AUC | 0.836 | **0.996** | **+0.160** |
| clean test, Acc | 0.990 | 0.992 | +0.002 (без регресії) |

Per-technique (accuracy):

| Технік | Baseline | Augmented | Δ |
|---|---:|---:|---:|
| `base64_strings` | 0.398 | **0.995** | **+0.597** |
| `marshal_wrap` | 0.377 | **0.869** | **+0.492** |
| `dead_code_inject` | 0.987 | 0.990 | +0.003 |
| `rename_identifiers` | 0.989 | 0.993 | +0.005 |
| `string_split` | 0.987 | 0.993 | +0.007 |

## Структура

```
.
├── docs/                  # research-документація
├── notebooks/             # end-to-end Jupyter notebook з графіками
├── src/
│   ├── collect/           # 5 джерел даних + DataDog extractor + splits
│   ├── obfuscate/         # 5 технік обфускації (AST-rewrites)
│   ├── models/            # baseline + augmented
│   └── eval/              # drift test + PDF renderer
├── data/
│   ├── raw/               # benign[/_real/_ambiguous] + malicious[/_real]
│   ├── obfuscated/        # 5 директорій по техніці
│   └── splits/            # *.jsonl manifests
├── artifacts/             # *.pkl (модель + векторизатор), *_metrics.json
└── reports/               # markdown + PDF звіти
```

## Pre-install scanner

Утиліта `src/scan/scan_package.py` використовує augmented-модель для перевірки PyPI-пакетів **до** встановлення. Скачує через `pip download --no-deps`, розпаковує, скорить кожен `.py` файл, видає verdict.

```bash
# Перевірити пакет з PyPI без встановлення
python3 -m src.scan.scan_package --name requests
python3 -m src.scan.scan_package --name suspicious-pkg==1.2.3

# Локальний архів / директорія / .py-файл
python3 -m src.scan.scan_package --file ./dist/mypkg-0.1.0.tar.gz
python3 -m src.scan.scan_package --file ./my_package_src/
python3 -m src.scan.scan_package --file ./suspicious.py

# JSON-вихід для CI/CD
python3 -m src.scan.scan_package --name requests --json
```

**Exit codes:** `0` SAFE, `1` SUSPICIOUS, `2` BLOCK, `3` ERROR — зручно для pre-install hooks і CI.

**Приклад виводу на real DataDog malware:**
```
Top files by malicious score:
   score  path                            parses
   0.998  malreal_00002.py                yes  <- MALICIOUS
   0.997  malreal_00001.py                yes  <- MALICIOUS
   ...

VERDICT: BLOCK
```

Потребує `artifacts/augmented_model.pkl` — створіть його через `notebooks/baseline_simple.ipynb` (або відповідний training script).

## Інтерпретація + застереження

1. **`marshal_wrap` recall = 79%** — після augmented training модель навчилась, що marshal-wrapping буває і у benign (наш wrapper для CSV-парсера), тому деякі справжні malicious-payloads, що покладаються тільки на marshal+exec, тепер проходять. У production треба окремий downstream-аналіз для marshal-content (entropy, unpack & re-scan).
2. **AST features — критичний компонент.** Без них (тільки текстові ngrams) drift на rename_identifiers був би сильнішим. `has_shell_kw`, `has_install_hook`, `num_subprocess` тримають метрики на технічних обфускаціях.
3. **Реальний benign з stdlib робить датасет правдоподібним.** До нього метрики baseline були 100% на всіх splits — не тому що задача проста, а тому що синтетичні темплейти лінійно роздільні. Реальний код має overlap (subprocess, getattr, base64 у легітимних утилітах).
4. **Що не покрито:** control-flow flattening, opaque predicates, native packing (pyarmor + .so stubs), pyc-only payloads. Для них потрібен dynamic-analysis шар або CodeBERT-class model.
