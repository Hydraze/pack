# PACK — Password Analysis and Cracking Kit

PACK is a collection of utilities to analyze password lists and turn what you
learn into effective attacks for the [hashcat](https://hashcat.net/hashcat/)
family of password crackers. It detects the masks, character sets, rules and
policies that people actually use, so you can prioritize the cheapest, most
productive candidates first.

> PACK does **not** crack passwords itself. It produces input files (masks,
> rules and wordlists) that make a real cracker far more efficient.

Originally written by Peter Kacherginsky (iphelix). This fork modernizes the
toolkit for current Python 3.

## What's in the box

| Tool           | Purpose                                                                 |
| -------------- | ----------------------------------------------------------------------- |
| `statsgen.py`  | Statistical analysis of a password list (length, charset, masks, …).    |
| `maskgen.py`   | Turn `statsgen` output into optimal, sorted hashcat masks (`.hcmask`).  |
| `policygen.py` | Generate masks matching (or violating) a password-complexity policy.    |
| `rulegen.py`   | Reverse source words and hashcat rules from already-cracked passwords.  |

## Requirements

- **Python 3.8+** (no third-party packages for `statsgen`, `maskgen` or
  `policygen` — standard library only).
- **`rulegen` only** additionally needs [PyEnchant](https://pyenchant.github.io/pyenchant/)
  plus the system `enchant` library and a dictionary.

On Debian/Ubuntu:

```bash
sudo apt install libenchant-2-2 aspell-en hunspell-en-us
```

## Installation

Clone and run the scripts directly:

```bash
git clone https://github.com/iphelix/pack.git
cd pack

# Optional: only needed for rulegen
pip install -r requirements.txt

python3 statsgen.py --help
```

Or install as a package to get the `statsgen`, `maskgen`, `policygen` and
`rulegen` commands on your `PATH`:

```bash
pip install .            # core tools
pip install '.[rulegen]' # also pull in pyenchant for rulegen
```

## Usage

### StatsGen — analyze a password list

```bash
python3 statsgen.py rockyou.txt
```

Reports the most common lengths, character sets, password complexity, and both
"simple" masks (e.g. `stringdigit`) and hashcat "advanced" masks
(e.g. `?l?l?l?l?l?l?l?l`). Useful flags:

- `--minlength` / `--maxlength`, `--charset`, `--simplemask` — filter the sample.
- `--hiderare` — hide items covering less than 1% of the sample.
- `-o out.masks` — save advanced masks with occurrences (feed this to `maskgen`).

```bash
python3 statsgen.py rockyou.txt -o rockyou.masks --hiderare
```

### MaskGen — build optimal masks

Consumes the `.masks` file produced by `statsgen -o` and emits a `.hcmask`
sorted by the *optimal index* (coverage vs. cost), occurrence, or complexity:

```bash
python3 maskgen.py rockyou.masks --optindex --showmasks -o rockyou.hcmask
```

- `-t 86400` — stop once the accumulated masks would take longer than N seconds.
- `--pps 1000000000` — cracking speed used for time estimates.
- Filters: `--minlength/--maxlength`, `--min/maxtime`, `--min/maxcomplexity`,
  `--min/maxoccurrence`.
- `--checkmasks '?u?l?l?l?l?l?d,...'` or `--checkmasksfile masks.hcmask` — report
  how much of your sample a given set of masks would cover.

### PolicyGen — masks for a password policy

Generate only the masks that satisfy (or, with `--noncompliant`, violate) a
complexity policy, avoiding wasted work on impossible candidates:

```bash
python3 policygen.py --minlength 8 --maxlength 8 \
    --minlower 1 --minupper 1 --mindigit 1 --minspecial 1 \
    -o complexity.hcmask
```

Add `--showmasks` to print each mask with its strength breakdown and estimated
runtime. Maximum bounds (`--maxlower/--maxupper/--maxdigit/--maxspecial`) let you
model sites that forbid certain classes (e.g. `--maxspecial 0`).

### RuleGen — reverse words and hashcat rules

Given already-cracked passwords, `rulegen` finds a likely dictionary source word
and the hashcat rule that transforms it into the password, using the Levenshtein
reverse-path algorithm and Enchant spell-checking. See the paper
[Automatic Password Rule Analysis and Generation](http://thesprawl.org/research/automatic-password-rule-analysis-generation/)
for the theory, and the [hashcat rule reference](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
for rule syntax.

Analyze a single password (prints the source word and rule):

```bash
python3 rulegen.py --password 'P@ssw0rd'
# [word] Password
# [rule] sa@ o50
```

Analyze a whole file — writes `analysis.rule` / `analysis.word` and their
frequency-sorted `-sorted` variants:

```bash
python3 rulegen.py rockyou.txt -b rockyou
```

Handy options:

- `-b BASENAME` — output base name.
- `-w wordlist.dict` — use a custom wordlist instead of the spell checker.
- `--providers aspell,hunspell` — choose enchant provider engines.
- `--maxwords` / `--maxworddist` and `--maxrules` / `--maxrulelen` — tune how many
  candidate words/rules are considered and how large they may get.
- `--simplewords` / `--simplerules` — faster, less thorough generation.
- `--bruterules` — also try reversal/rotation pre-rules (slower).
- `-v` / `-d` — verbose / debug output.

## What changed in this modernized fork

- Ported the command-line interface of all four tools from the deprecated
  `optparse` to `argparse`.
- Made `rulegen`'s `pyenchant` dependency optional with a clear install message
  instead of a raw `ImportError`, and switched the default provider list from the
  legacy `aspell,myspell` to `aspell,hunspell` (enchant-2).
- `rulegen --password` now prints the generated word and rule directly instead of
  silently discarding them.
- Fixed several bugs: word-frequency percentages summed the wrong counter; the
  extract (`x`) rule collided with the truncate (`'`) rule; a debug line was a
  no-op string instead of a `print`.
- Guarded against division-by-zero and file-handle leaks on empty inputs, and
  wrapped file access in context managers.
- Added packaging (`pyproject.toml`, `requirements.txt`) with console entry points
  and a `.gitignore`.

## License

See [LICENSE](LICENSE). PACK is provided for authorized security testing,
password audits, and research.
