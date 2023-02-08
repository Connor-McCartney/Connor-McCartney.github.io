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
from os import system
from random import randint

stockfish = Stockfish(path="/usr/bin/stockfish")
s = requests.Session()
lichess_api_key = "..."
cookie = "lila2=..."


def new_game():
    print("new game")
    requests.Session().post('https://lichess.org/setup/hook/XXXXXXXXXXXX', json={"variant":"1", "mode":"1", "timeMode":"1", "time":"10", "increment":"0", "days":"2", "days_range":"2", "color":"random"}, headers={'cookie': cookie})

new_game()
opened_in_firefox = []
while True:
    req = s.get("https://lichess.org/api/account/playing", headers={"Authorization": f"Bearer {lichess_api_key}", "Content-Type": "application/json"})
    nowPlaying = loads(req.text)["nowPlaying"]
    waiting_for_everyone = True
    for data in nowPlaying:
        if not data["isMyTurn"]:
            print("still their turn")
            continue
        waiting_for_everyone = False
        stockfish.set_fen_position(data["fen"])
        move = stockfish.get_best_move_time(randint(1, 3) * 1000)
        print(move)
        game = data["gameId"]
        if game not in opened_in_firefox:
            opened_in_firefox.append(game)
            system(f"firefox https://lichess.org/{game}")
        s.post(f"https://lichess.org/api/board/game/{game}/move/{move}", headers={"Authorization": f"Bearer {lichess_api_key}"})
    if waiting_for_everyone:
        new_game()

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
