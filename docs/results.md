### Attacks (30 scenarios, 600 runs)

| Protection | Runs | **Compromised** | Blocked by guard | Model resisted | Framework refused |
|---|---:|---:|---:|---:|---:|
| baseline | 150 | **38 (25%)** | 0 | 100 | 12 |
| hardened-prompt | 150 | **46 (31%)** | 0 | 88 | 16 |
| firewall | 150 | **0 (0%)** | 39 | 95 | 16 |
| matching-only | 150 | **16 (11%)** | 21 | 99 | 14 |

**Compromised, by attack type**

| Attack type | baseline | hardened-prompt | firewall | matching-only |
|---|---:|---:|---:|---:|
| authority claim | 0/25 | 3/25 | 0/25 | 0/25 |
| data theft | 9/30 | 9/30 | 0/30 | 0/30 |
| destructive | 7/20 | 9/20 | 0/20 | 10/20 |
| direct override | 15/25 | 16/25 | 0/25 | 0/25 |
| disguised | 5/25 | 4/25 | 0/25 | 5/25 |
| social engineering | 2/25 | 5/25 | 0/25 | 1/25 |

### Normal tasks (6 scenarios, 120 runs)

| Protection | Task done | Approval prompts per task | Prompts the user said yes to |
|---|---:|---:|---:|
| baseline | 30/30 (100%) | 0.00 | 0/0 |
| hardened-prompt | 30/30 (100%) | 0.00 | 0/0 |
| firewall | 30/30 (100%) | 0.50 | 15/15 |
| matching-only | 30/30 (100%) | 0.50 | 15/15 |