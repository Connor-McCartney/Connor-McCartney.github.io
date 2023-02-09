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

stockfish = Stockfish(path="/usr/bin/stockfish")
s = requests.Session()
lichess_api_key = "..."
cookie = "lila2=..."


def new_game():
    print("new game")
    s.post('https://lichess.org/setup/hook/XXXXXXXXXXXX', json={"variant":"1", "mode":"1", "timeMode":"1", "time":"10", "increment":"0", "days":"2", "days_range":"2", "color":"random"}, headers={'cookie': cookie})

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
        move = stockfish.get_best_move_time(300)
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
from pynput.mouse import Button, Controller
from time import sleep

mouse = Controller()
s = requests.Session()
lichess_api_key = "lip_4Cxq84cF0uv1n8W6VKdO"
cookie = "lila2=48208b9dfb0d76926a9d177736d186d1e7310e7b-sid=zlzBV6zZsMZV7oA6rxgMX8&sessionId=wkRYZHGGzF7FoJR2ylHPCq&bg=dark"

def click():
    mouse.press(Button.left)
    mouse.release(Button.left)
    sleep(0.3)

def refresh():
    mouse.position = (121, 116)
    click()
    sleep(1.5)

def move(solution, turn):
    width = 96
    bottomleft_x = 600
    bottomleft_y = 920
    map_black_letters = {'h': 0, 'g': 1, 'f': 2, 'e': 3, 'd': 4, 'c': 5, 'b': 6, 'a': 7}
    map_black_numbers = {'8': 0, '7': 1, '6': 2, '5': 3, '4': 4, '3': 5, '2': 6, '1': 7}
    map_white_letters = {'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6, 'h': 7}
    map_white_numbers = {'1': 0, '2': 1, '3': 2, '4': 3, '5': 4, '6': 5, '7': 6, '8': 7}
    if turn == "black":
        for move in solution:
            mouse.position = (bottomleft_x + width * map_black_letters[move[0]], bottomleft_y - width * map_black_numbers[move[1]])
            click()
            mouse.position = (bottomleft_x + width * map_black_letters[move[2]], bottomleft_y - width * map_black_numbers[move[3]])
            click()
            if move[3] == '1':
                click()
                mouse.press(Button.left)
                mouse.release(Button.left)
    if turn == "white":
        for move in solution:
            mouse.position = (bottomleft_x + width * map_white_letters[move[0]], bottomleft_y - width * map_white_numbers[move[1]])
            click()
            mouse.position = (bottomleft_x + width * map_white_letters[move[2]], bottomleft_y - width * map_white_numbers[move[3]])
            click()
            if move[3] == '8':
                click()
                mouse.press(Button.left)
                mouse.release(Button.left)

def main():
    req = s.get('https://lichess.org/training', headers={'Accept-Encoding': 'br', 'cookie': cookie})
    line = req.content.decode().split("\n")[0]
    id = line.split("Chess tactic #")[1][:5]
    print(f"{id = }")
    turn = line.split("Find the best move for ")[1][:5]
    print(f"{turn = }")

    req = s.get(f"https://lichess.org/api/puzzle/{id}", headers={"Authorization": f"Bearer {lichess_api_key}", "Content-Type": "application/json"})
    moves = loads(req.text)['puzzle']['solution']
    solution = []
    for i in range(0, len(moves), 2):
        solution.append(moves[i])
    print(f"{solution = }")
    move(solution, turn)

    #req = s.post(f'https://lichess.org/training/complete/mix/{id}', json={'win': 'true', 'rated': 'true'}, headers={'cookie': cookie})
    #print(req.status_code)

if __name__ == "__main__":
    sleep(3)
    while True:
        refresh()
        main()
```
