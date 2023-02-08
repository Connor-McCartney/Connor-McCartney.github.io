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
    move = stockfish.get_best_move_time(200)
    game = data["gameId"]
    s.post(f"https://lichess.org/api/board/game/{game}/move/{move}", headers={"Authorization": f"Bearer {lichess_api_key}"})

```

Starting games:

```python
import requests
from time import sleep

s = requests.Session()
cookie = "lila2=..."

while True:
    r = s.post('https://lichess.org/setup/hook/XXXXXXXXXXXX', json={"variant":"1", "mode":"1", "timeMode":"1", "time":"10", "increment":"0", "days":"2", "days_range":"2", "color":"random"}, headers={'cookie': cookie})
    print(r.ok)
    sleep(2)
```


Puzzles:

```python
import requests
from json import loads

s = requests.Session()
lichess_api_key = "..."
cookie = "lila2=..."

def main():
    req = s.get('https://lichess.org/training', headers={'Accept-Encoding': 'br', 'cookie': cookie})
    line = req.content.decode().split("\n")[0]
    id = line.split("Chess tactic #")[1][:5]
    print(f"{id = }")
    turn = line.split("Find the best move for ")[1][:5]
    print(f"{turn = }")

    #req = s.get(f"https://lichess.org/api/puzzle/{id}", headers={"Authorization": f"Bearer {lichess_api_key}", "Content-Type": "application/json"})
    #moves = loads(req.text)['puzzle']['solution']
    #solution = []
    #for i in range(0, len(moves), 2):
    #    solution.append(moves[i])
    #print(f"{solution = }")

    req = s.post(f'https://lichess.org/training/complete/mix/{id}', json={'win': 'true', 'rated': 'true'}, headers={'cookie': cookie})
    print(req.status_code)

if __name__ == "__main__":
    while True:
        main()
```
