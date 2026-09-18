from pathlib import Path
from evaluation.harness.replay import FixtureReplay

def test_replay_uses_real_normaliser():
    root=Path(__file__).resolve().parents[2]
    events=FixtureReplay(root).replay(root/'evaluation/fixtures/attack/defense_evasion.json')
    assert len(events)==1 and events[0].event=='StopLogging' and events[0].event_id=='de0'
