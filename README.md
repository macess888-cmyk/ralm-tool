# RALM v0.2

Ratio-to-Alphabet Link Mapper with HACR-ALL observer.

## Baseline
- rule: A1Z26
- mode: fail-closed
- directions:
  - forward = numbers -> letters
  - reverse = letters -> numbers
- observer: HACR-ALL
- receipts stored in `receipts/`
- failed receipts moved to `receipts/failed/`

## Commands

### Forward map
python ralm\main.py map --rule a1z26 --mode fail-closed --direction forward --input 8,1,3,18

### Reverse map
python ralm\main.py map --rule a1z26 --mode fail-closed --direction reverse --input HACR

### Audit latest receipt
python ralm\main.py audit --last

### Audit all active receipts
python ralm\main.py audit --all

### List active receipts
python ralm\main.py list-receipts

### Show latest receipt
python ralm\main.py show --last

### Export summary
python ralm\main.py export-summary

### List summaries
python ralm\main.py list-summaries

### Show latest summary
python ralm\main.py show-summary --last

### Clean failed receipts
python ralm\main.py clean-failed

## Expected baseline tests

### Forward
python ralm\main.py map --rule a1z26 --mode fail-closed --direction forward --input 8,1,3,18

Expected:
- output: HACR
- status: PASS

### Reverse
python ralm\main.py map --rule a1z26 --mode fail-closed --direction reverse --input HACR

Expected:
- output: [8, 1, 3, 18]
- status: PASS