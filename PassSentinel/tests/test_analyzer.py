import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from analyzer import analyze, rate

def test_common_password_is_very_weak():
    r = analyze("password")
    assert r["flags"]["common"] and rate(r["bits"]) == 0

def test_leetspeak_word_detected():
    assert analyze("Sunsh1ne!!")["flags"]["word"]

def test_sequence_and_year():
    r = analyze("xk9abc2024")
    assert r["flags"]["seq"] and r["flags"]["year"]

def test_random_long_is_strong():
    assert rate(analyze("vT7#qLm2$Zp9!xRw4Kd8")["bits"]) >= 3

def test_empty():
    assert analyze("")["bits"] == 0
