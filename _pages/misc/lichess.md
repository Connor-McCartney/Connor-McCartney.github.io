---
permalink: /misc/lichess
title: Automating playing on lichess
---

<br>

Lichess let's you create a token at <https://lichess.org/account/oauth/token/create> which can let you <br>
get positions and send moves (plus much more!) <br>
This script I wrote abuses it to cheat at chess <br>
I found it works for rapid and classical but not blitz/bullet chess.

```python
import requests
from json import loads
from stockfish import Stockfish

stockfish = Stockfish(path="/usr/bin/stockfish")
s = requests.Session()
lichess_api_key = "..."

while True:
    req = s.get("https://lichess.org/api/account/playing", headers={"Authorization": f"Bearer {lichess_api_key}", "Content-Type": "application/json"})
    data = loads(req.text)["nowPlaying"][0]
    if not data["isMyTurn"]:
        continue
    stockfish.set_fen_position(data["fen"])
    move = stockfish.get_best_move_time(1000)
    game = data["gameId"]
    req = s.post
```
