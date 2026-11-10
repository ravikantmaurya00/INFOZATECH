"""Password analysis engine: entropy with pattern penalties."""
import math
import re

COMMON = ("123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,"
          "football,monkey,letmein,shadow,master,qwertyuiop,mustang,1234567890,superman,1qaz2wsx,trustno1,"
          "iloveyou,sunshine,princess,welcome,admin,login,passw0rd,p@ssw0rd,password1,password123,admin123,"
          "qwerty123,000000,654321,555555,starwars,whatever,freedom,batman,zaq12wsx,hello123,india123").split(",")

WORDS = sorted(set((
    "password,admin,welcome,login,qwerty,dragon,monkey,master,letmein,shadow,sunshine,princess,football,"
    "baseball,iloveyou,superman,batman,hello,secret,summer,winter,spring,autumn,love,angel,flower,freedom,"
    "whatever,cookie,coffee,ninja,hunter,soccer,tiger,lucky,magic,pepper,ranger,thunder,michael,jessica,"
    "charlie,daniel,jennifer,ashley,cheese,computer,internet,killer,london,mother,orange,purple,silver,"
    "yellow,access,india,cricket,lucknow,family,google,apple,monsoon,mango,delhi,mumbai,sachin,virat,"
    "bollywood,school,house,money,happy,music,pizza,dog,cat").split(",")), key=len, reverse=True)

KEYROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]
LEET_I = str.maketrans({"1": "i", "!": "i", "|": "i", "@": "a", "4": "a", "3": "e", "0": "o", "$": "s", "5": "s", "7": "t"})
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "0": "o", "$": "s", "5": "s", "7": "t", "!": "i", "1": "l", "|": "l"})


def pool_size(p: str) -> int:
    n = 0
    if re.search(r"[a-z]", p): n += 26
    if re.search(r"[A-Z]", p): n += 26
    if re.search(r"\d", p): n += 10
    if re.search(r"[^A-Za-z0-9]", p): n += 33
    return n


def rate(bits: float) -> int:
    """0 = very weak ... 4 = excellent."""
    return 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4


def analyze(pw: str) -> dict:
    n, pool = len(pw), pool_size(pw)
    flags = dict(common=False, word=False, seq=False, year=False, rep=False)
    if not n:
        return dict(n=0, pool=0, bits=0, segs=[], flags=flags)

    low = "".join((c.lower() or c)[0] for c in pw)
    leet = low.translate(LEET)
    mark = [None] * n
    counter = [0]

    def free(a, b):
        return all(mark[i] is None for i in range(a, b))

    def put(a, b, kind, bits):
        if not free(a, b):
            return
        counter[0] += 1
        for i in range(a, b):
            mark[i] = (kind, counter[0], bits if i == a else 0)

    lp = math.log2(pool or 1)

    for m in re.finditer(r"(.{1,4}?)\1+", low):            # repeats
        if len(m.group()) >= 3:
            put(m.start(), m.end(), "rep", 3 + math.log2(len(m.group())) + lp * len(m.group(1)) * 0.5)
            flags["rep"] = True

    i = 0                                                    # runs like abc / 321
    while i < n - 2:
        d = ord(low[i + 1]) - ord(low[i])
        if abs(d) == 1:
            j = i + 1
            while j + 1 < n and ord(low[j + 1]) - ord(low[j]) == d:
                j += 1
            if j - i + 1 >= 3:
                put(i, j + 1, "seq", 5 + math.log2(j - i + 1))
                flags["seq"] = True
                i = j
                continue
        i += 1

    for row in KEYROWS:                                      # keyboard walks
        for r in (row, row[::-1]):
            for length in range(min(len(r), n), 2, -1):
                for s in range(len(r) - length + 1):
                    sub = r[s:s + length]
                    k = low.find(sub)
                    while k >= 0:
                        if free(k, k + length):
                            put(k, k + length, "seq", 6 + math.log2(length))
                            flags["seq"] = True
                        k = low.find(sub, k + 1)

    for m in re.finditer(r"(?:19|20)\d{2}", pw):             # years
        put(m.start(), m.end(), "year", 7)
        flags["year"] = True

    for variant in (leet, low.translate(LEET_I)):            # dictionary + leetspeak (1 can be l or i)
        for w in WORDS:
            k = variant.find(w)
            while k >= 0:
                if free(k, k + len(w)):
                    b = 12 + (2 if variant[k:k + len(w)] != low[k:k + len(w)] else 0)
                    if any(c.isupper() for c in pw[k:k + len(w)]):
                        b += 1.5
                    put(k, k + len(w), "word", b)
                    flags["word"] = True
                k = variant.find(w, k + 1)

    bits, segs = 0.0, []
    for x in range(n):
        c = mark[x]
        if c is None:
            bits += lp
            segs.append(dict(t=pw[x], type="rand"))
        else:
            bits += c[2]
            if segs and segs[-1].get("id") == c[1]:
                segs[-1]["t"] += pw[x]
            else:
                segs.append(dict(t=pw[x], type=c[0], id=c[1]))

    if low in COMMON or leet in COMMON:
        rank = COMMON.index(low) if low in COMMON else COMMON.index(leet)
        bits = min(bits, math.log2(rank + 2) + 2)
        flags["common"] = True
        segs = [dict(t=pw, type="common")]

    return dict(n=n, pool=pool, bits=round(bits, 2), segs=segs, flags=flags)
