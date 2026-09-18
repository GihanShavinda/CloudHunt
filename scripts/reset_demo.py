from __future__ import annotations
from pathlib import Path

def main():
    root=Path(__file__).resolve().parents[1]
    removed=0
    for name in ('evaluation.json','evaluation.csv','evaluation.html','attack_coverage.json'):
        p=root/'evaluation'/'reports'/name
        if p.exists(): p.unlink(); removed += 1
    print(f'Removed {removed} generated evaluation report(s). Application data was not touched.')
if __name__=='__main__': main()
