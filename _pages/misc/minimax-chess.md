---
permalink: /misc/minimax-chess
title: Minimax chess algorithm
---

<br>


```python
from enum import IntEnum
from curses import wrapper, curs_set, init_pair, COLOR_RED, COLOR_BLACK, color_pair
from random import choice
from time import sleep

class Highlights(IntEnum):
    NORMAL = 0
    CHECK = 1

class Colours(IntEnum):
    WHITE = 1
    EMPTY = 0
    BLACK = -1

class Pieces(IntEnum):
    ROOK = 0
    KNIGHT = 1
    BISHOP = 2
    QUEEN = 3
    KING = 4
    PAWN = 5
    BLANK = 6

class Piece:
    def __init__(self, unicode_char, colour, piece):
        self.unicode_char = unicode_char
        self.colour = colour
        self.piece = piece

class Move:
    def __init__(self, start_x, start_y, end_x, end_y):
        self.start_x = start_x
        self.start_y = start_y
        self.end_x = end_x
        self.end_y = end_y
    def __repr__(self):
        return f'{self.start_x}{self.start_y}{self.end_x}{self.end_y}'

class Square():
    def __init__(self, piece, x, y, highlight):
        self.piece = piece
        self.x = x
        self.y = y
        self.highlight = highlight

class Position():
    def __init__(self, board, turn, can_black_castle_kingside, can_black_castle_queenside,
               can_white_castle_kingside, can_white_castle_queenside, en_passant):
        self.board = board
        self.turn = turn
        self.can_black_castle_kingside = can_black_castle_kingside
        self.can_black_castle_queenside = can_black_castle_queenside
        self.can_white_castle_kingside = can_white_castle_kingside
        self.can_white_castle_queenside = can_white_castle_queenside
        self.en_passant = en_passant

white_rook = Piece("♜", Colours.WHITE, Pieces.ROOK)
white_knight = Piece("♞", Colours.WHITE, Pieces.KNIGHT)
white_bishop = Piece("♝", Colours.WHITE, Pieces.BISHOP)
white_queen = Piece("♛", Colours.WHITE, Pieces.QUEEN)
white_king = Piece("♚", Colours.WHITE, Pieces.KING)
white_pawn = Piece("♟", Colours.WHITE, Pieces.PAWN)
black_rook = Piece("♖", Colours.BLACK, Pieces.ROOK)
black_knight = Piece("♘", Colours.BLACK, Pieces.KNIGHT)
black_bishop = Piece("♗", Colours.BLACK, Pieces.BISHOP)
black_queen = Piece("♕", Colours.BLACK, Pieces.QUEEN)
black_king = Piece("♔", Colours.BLACK, Pieces.KING)
black_pawn = Piece("♙", Colours.BLACK, Pieces.PAWN)
empty = Piece(" ", Colours.EMPTY, Pieces.BLANK)

def draw_board(stdscr, game_position):
    if is_check(game_position):
        king_x, king_y = get_king_position(game_position)
        game_position.board[king_x][king_y].highlight = Highlights.CHECK
    highlight = None
    for i in range(8):
        for j in range(8):
            match game_position.board[i][j].highlight:
                case Highlights.NORMAL:
                    WHITE = color_pair(0)
                    highlight = WHITE
                case Highlights.CHECK:
                    RED = color_pair(1)
                    highlight = RED
            piece = game_position.board[i][j].piece;
            stdscr.addstr(15 - 2*j, 6 + 4*i, piece.unicode_char, highlight)
    stdscr.refresh()

def initialise_board(game_position):
    game_position.board = [[Square(empty, x, y, Highlights.NORMAL) for x in range(8)] for y in range(8)]
    for i in range(8):
        game_position.board[i][1].piece = white_pawn;
        game_position.board[i][6].piece = black_pawn;

    game_position.board[0][0].piece = white_rook;
    game_position.board[1][0].piece = white_knight;
    game_position.board[2][0].piece = white_bishop;
    game_position.board[3][0].piece = white_queen;
    game_position.board[4][0].piece = white_king;
    game_position.board[5][0].piece = white_bishop;
    game_position.board[6][0].piece = white_knight;
    game_position.board[7][0].piece = white_rook;

    game_position.board[0][7].piece = black_rook;
    game_position.board[1][7].piece = black_knight;
    game_position.board[2][7].piece = black_bishop;
    game_position.board[3][7].piece = black_queen;
    game_position.board[4][7].piece = black_king;
    game_position.board[5][7].piece = black_bishop;
    game_position.board[6][7].piece = black_knight;
    game_position.board[7][7].piece = black_rook;

def draw_border(stdscr):
    border = "\
    \r    ┌───┬───┬───┬───┬───┬───┬───┬───┐\n\
    \r  8 │   │   │   │   │   │   │   │   │\n\
    \r    ├───┼───┼───┼───┼───┼───┼───┼───┤\n\
    \r  7 │   │   │   │   │   │   │   │   │\n\
    \r    ├───┼───┼───┼───┼───┼───┼───┼───┤\n\
    \r  6 │   │   │   │   │   │   │   │   │\n\
    \r    ├───┼───┼───┼───┼───┼───┼───┼───┤\n\
    \r  5 │   │   │   │   │   │   │   │   │\n\
    \r    ├───┼───┼───┼───┼───┼───┼───┼───┤\n\
    \r  4 │   │   │   │   │   │   │   │   │\n\
    \r    ├───┼───┼───┼───┼───┼───┼───┼───┤\n\
    \r  3 │   │   │   │   │   │   │   │   │\n\
    \r    ├───┼───┼───┼───┼───┼───┼───┼───┤\n\
    \r  2 │   │   │   │   │   │   │   │   │\n\
    \r    ├───┼───┼───┼───┼───┼───┼───┼───┤\n\
    \r  1 │   │   │   │   │   │   │   │   │\n\
    \r    └───┴───┴───┴───┴───┴───┴───┴───┘\n\
    \r      a   b   c   d   e   f   g   h  \n\
    \r                                     \n"

    stdscr.addstr(0, 0, border)
    stdscr.refresh()

def get_possible_rook_moves(game_position, x, y):
    col = game_position.board[x][y].piece.colour
    possible_moves = []
    up_down = [0, 0, -1, 1]
    left_right = [-1, 1, 0, 0]
    for i in range(4):
        yy = y;
        xx = x;
        while True:
            xx += left_right[i];
            yy += up_down[i];
            if (xx > 7 or yy > 7 or xx < 0 or yy < 0):
                break
            if (game_position.board[xx][yy].piece.colour != col):
                move = Move(x, y, xx, yy)
                possible_moves.append(move)
            if (game_position.board[xx][yy].piece.colour != Colours.EMPTY):
                break
    return possible_moves

def get_possible_knight_moves(game_position, x, y):
    col = game_position.board[x][y].piece.colour;
    possible_moves = []
    for i in range(-2, 3):
        for j in range(-2, 3):
            if (i==0 or j==0 or abs(i)== abs(j)):
                continue
            yy = y + i
            xx = x + j
            if (xx > 7 or yy > 7 or xx < 0 or yy < 0):
                continue
            if (game_position.board[xx][yy].piece.colour != col):
                move = Move(x, y, xx, yy)
                possible_moves.append(move)
            if (game_position.board[xx][yy].piece.colour != Colours.EMPTY):
                continue
    return possible_moves

def get_possible_king_moves(game_position, x, y):
    col = game_position.board[x][y].piece.colour
    possible_moves = []
    for i in [-1, 0, 1]:
        for j in [-1, 0, 1]:
            yy = y + i
            xx = x + j
            if (xx > 7 or yy > 7 or xx < 0 or yy < 0):
                continue
            if (game_position.board[xx][yy].piece.colour != col):
                move = Move(x, y, xx, yy)
                possible_moves.append(move)
            if (game_position.board[xx][yy].piece.colour != Colours.EMPTY):
                continue

    # castle kingside
    if col == Colours.WHITE:
        if (game_position.board[5][0].piece.colour == Colours.EMPTY and
                game_position.board[6][0].piece.colour == Colours.EMPTY and
                game_position.can_white_castle_kingside):
            move = Move(x, y, x+2, y)
            possible_moves.append(move)
    if col == Colours.BLACK:
        if (game_position.board[5][7].piece.colour == Colours.EMPTY and
                game_position.board[6][7].piece.colour == Colours.EMPTY and
                game_position.can_black_castle_kingside):
            move = Move(x, y, x+2, y)
            possible_moves.append(move)

    # castle queenside
    if col == Colours.WHITE:
        if (game_position.board[3][0].piece.colour == Colours.EMPTY and
                game_position.board[2][0].piece.colour == Colours.EMPTY and
                game_position.can_white_castle_queenside):
            move = Move(x, y, x-2, y)
            possible_moves.append(move)
    if col == Colours.BLACK:
        if (game_position.board[3][7].piece.colour == Colours.EMPTY and
                game_position.board[2][7].piece.colour == Colours.EMPTY and
                game_position.can_black_castle_queenside):
            move = Move(x, y, x-2, y)
            possible_moves.append(move)

    return possible_moves

def get_possible_queen_moves(game_position, x, y):
    col = game_position.board[x][y].piece.colour
    possible_moves = []
    for i in [-1, 0, 1]:
        for j in [-1, 0, 1]:
            yy = y
            xx = x
            while True:
                xx += i
                yy += j
                if (xx > 7 or yy > 7 or xx < 0 or yy < 0):
                    break
                if (game_position.board[xx][yy].piece.colour != col):
                    move = Move(x, y, xx, yy)
                    possible_moves.append(move)
                if (game_position.board[xx][yy].piece.colour != Colours.EMPTY):
                    break
    return possible_moves

def get_possible_bishop_moves(game_position, x, y):
    col = game_position.board[x][y].piece.colour
    possible_moves = []
    for i in [-1, 1]:
        for j in [-1, 1]:
            yy = y
            xx = x
            while True:
                xx += i
                yy += j
                if (xx > 7 or yy > 7 or xx < 0 or yy < 0):
                    break
                if (game_position.board[xx][yy].piece.colour != col):
                    move = Move(x, y, xx, yy)
                    possible_moves.append(move)
                if (game_position.board[xx][yy].piece.colour != Colours.EMPTY):
                    break
    return possible_moves

def get_possible_pawn_moves(game_position, x, y):
    col = game_position.board[x][y].piece.colour
    possible_moves = []
    if ((col == Colours.WHITE and y == 1) or (col == Colours.BLACK and y == 6)):
        # forward 1 or 2 squares
        yy = y
        for _ in range(2):
            yy += col.value
            if (game_position.board[x][yy].piece.colour == Colours.EMPTY):
                move = Move(x, y, x, yy)
                possible_moves.append(move)
            else:
                break
    else:
        # forward only 1 square
        yy = y
        yy += col
        if (yy <= 7 and yy >= 0):
            if (game_position.board[x][yy].piece.colour == Colours.EMPTY):
                move = Move(x, y, x, yy)
                possible_moves.append(move)

    # captures
    for i in [-1, 1]:
        xx = x + i
        yy = y + col.value
        if (xx <= 7 and yy <= 7 and xx >= 0 and yy >= 0):
            if game_position.board[xx][yy].piece.colour == -col.value:
                move = Move(x, y, xx, yy)
                possible_moves.append(move)
            # en passant
            if xx == game_position.en_passant:
                if (y == 3 and col == Colours.BLACK) or (y == 4 and col == Colours.WHITE):
                    move = Move(x, y, xx, yy)
                    possible_moves.append(move)
    return possible_moves

def get_piece_possible_moves(game_position, x, y):
    possible_moves = []
    match game_position.board[x][y].piece.piece:
        case Pieces.KING:
            possible_moves = get_possible_king_moves(game_position, x, y)
        case Pieces.PAWN:
            possible_moves = get_possible_pawn_moves(game_position, x, y)
        case Pieces.KNIGHT:
            possible_moves = get_possible_knight_moves(game_position, x, y)
        case Pieces.ROOK:
            possible_moves = get_possible_rook_moves(game_position, x, y)
        case Pieces.QUEEN:
            possible_moves = get_possible_queen_moves(game_position, x, y)
        case Pieces.BISHOP:
            possible_moves = get_possible_bishop_moves(game_position, x, y)
    return possible_moves

def swap_turn(game_position):
    if game_position.turn == Colours.WHITE:
        game_position.turn = Colours.BLACK
    elif game_position.turn == Colours.BLACK:
        game_position.turn = Colours.WHITE

def is_square_check(game_position, x, y):
    ret = False
    swap_turn(game_position)
    possible_moves = get_all_possible_moves(game_position)
    swap_turn(game_position)
    for possible_move in possible_moves:
        end_x = possible_move.end_x
        end_y = possible_move.end_y
        if end_x == x and end_y == y:
            ret = True;
    return ret

def get_king_position(game_position):
    for x in range(8):
        for y in range(8):
            if (game_position.board[x][y].piece.piece == Pieces.KING and 
                game_position.board[x][y].piece.colour == game_position.turn):
                return x, y
    assert False

def is_check(game_position):
    king_x, king_y = get_king_position(game_position)
    return is_square_check(game_position, king_x, king_y)

def move_piece(game_position, move):
    start = game_position.board[move.start_x][move.start_y].piece
    end = game_position.board[move.end_x][move.end_y].piece

    ######################################################################
    # if we move a rook we can't castle anymore
    if start.piece == Pieces.ROOK and start.colour == Colours.WHITE:
        if move.start_x == 0 and move.start_y == 0:
            game_position.can_white_castle_queenside = False
        if move.start_x == 7 and move.start_y == 0:
            game_position.can_white_castle_kingside = False
    if start.piece == Pieces.ROOK and start.colour == Colours.BLACK:
        if move.start_x == 0 and move.start_y == 7:
            game_position.can_black_castle_queenside = False
        if move.start_x == 7 and move.start_y == 7:
            game_position.can_black_castle_kingside = False

    # if we move a king we can't castle anymore
    if start.piece == Pieces.KING and start.colour == Colours.WHITE:
        game_position.can_white_castle_queenside = False
        game_position.can_white_castle_kingside = False
    if start.piece == Pieces.KING and start.colour == Colours.BLACK:
        game_position.can_black_castle_queenside = False
        game_position.can_black_castle_kingside = False
    
    # if a pawn moves 2 squares, it has the possibility of being captured en passant
    white_pawn_moved_2_squares = (start.piece == Pieces.PAWN and start.colour == Colours.WHITE
                                    and move.start_y == 1 and move.end_y == 3)
    black_pawn_moved_2_squares = (start.piece == Pieces.PAWN and start.colour == Colours.BLACK
                                    and move.start_y == 6 and move.end_y == 4)
    if white_pawn_moved_2_squares or black_pawn_moved_2_squares:
        game_position.en_passant = move.start_x
    else:
        game_position.en_passant = -1
    #########################################################################

    # I'll just auto-queen instead of making an underpromotion popup
    if (start.piece == Pieces.PAWN and start.colour == Colours.WHITE and move.end_y == 7):
        game_position.board[move.end_x][move.end_y].piece = white_queen
        game_position.board[move.start_x][move.start_y].piece = empty
        return
    if (start.piece == Pieces.PAWN and start.colour == Colours.BLACK and move.end_y == 0):
        game_position.board[move.end_x][move.end_y].piece = black_queen;
        game_position.board[move.start_x][move.start_y].piece = empty;
        return

    # en passant
    if (start.piece == Pieces.PAWN and move.start_x != move.end_x and end.colour == Colours.EMPTY):
        game_position.board[move.end_x][move.end_y].piece = start
        game_position.board[move.end_x][move.start_y].piece = empty

    # castling
    if start.piece == Pieces.KING:
        if start.colour == Colours.WHITE:
            yy = 0
            new_rook = white_rook
        else:
            new_rook = black_rook
            yy = 7
        if move.start_x == 4 and move.start_y == yy and move.end_y == yy:
            if move.end_x == 6: # kingside
                game_position.board[move.end_x][move.end_y].piece = start 
                game_position.board[move.start_x][move.start_y].piece = empty 
                game_position.board[7][move.end_y].piece = empty # rook disappears
                game_position.board[5][move.end_y].piece = new_rook # rook moves to other side
                return
            if move.end_x == 2: # queenside
                game_position.board[move.end_x][move.end_y].piece = start 
                game_position.board[move.start_x][move.start_y].piece = empty 
                game_position.board[0][move.end_y].piece = empty # rook disappears
                game_position.board[3][move.end_y].piece = new_rook # rook moves to other side
                return

    # regular moves
    game_position.board[move.end_x][move.end_y].piece = start # piece at end becomes piece at start
    game_position.board[move.start_x][move.start_y].piece = empty #piece at start becomes empty

def copy_position(position):
    board_copy = [[Square(square.piece, square.x, square.y, square.highlight) for square in i] for i in position.board]
    position_copy = Position(board_copy, 
                                  position.turn, 
                                  position.can_black_castle_kingside, 
                                  position.can_black_castle_queenside,
                                  position.can_white_castle_kingside, 
                                  position.can_white_castle_queenside,
                                  position.en_passant)
    return position_copy

def get_piece_legal_moves(game_position, x, y):
    possible_moves = get_piece_possible_moves(game_position, x, y)
    legal_moves = []
    for possible_move in possible_moves:
        game_position_copy = copy_position(game_position)
        move_piece(game_position_copy, possible_move)

        # if castling, ensure we don't move through check
        start = game_position.board[possible_move.start_x][possible_move.start_y].piece
        if start.piece == Pieces.KING:
            if start.colour == Colours.WHITE:
                yy = 0
            else:
                yy = 7
            if possible_move.start_x == 4 and possible_move.start_y == yy and possible_move.end_y == y:
                if possible_move.end_x == 6: # kingside
                    if is_square_check(game_position_copy, 4, yy) or is_square_check(game_position_copy, 5, yy):
                        continue
                if possible_move.end_x == 2: # queenside
                    if is_square_check(game_position_copy, 4, yy) or is_square_check(game_position_copy, 3, yy):
                        continue

        # ensure we don't move into check
        if is_check(game_position_copy): 
            continue

        legal_moves.append(possible_move)
    return legal_moves

def get_all_legal_moves(game_position):
    all_legal_moves = []
    for x in range(8):
        for y in range(8):
            piece = game_position.board[x][y].piece
            if (piece.colour != game_position.turn):
                continue
            legal_moves = get_piece_legal_moves(game_position, x, y)
            for legal_move in legal_moves:
                move_copy = Move(legal_move.start_x, legal_move.start_y, legal_move.end_x, legal_move.end_y)
                all_legal_moves.append(move_copy)
    return all_legal_moves

def get_all_possible_moves(game_position):
    all_possible_moves = []
    for x in range(8):
        for y in range(8):
            piece = game_position.board[x][y].piece
            if (piece.colour != game_position.turn):
                continue
            possible_moves = get_piece_possible_moves(game_position, x, y)
            for possible_move in possible_moves:
                move_copy = Move(possible_move.start_x, possible_move.start_y, possible_move.end_x, possible_move.end_y)
                all_possible_moves.append(move_copy)
    return all_possible_moves

def check_game_over(stdscr, game_position):
    legal_moves = get_all_legal_moves(game_position)
    if legal_moves == []:
        if is_check(game_position):
            stdscr.addstr(19, 3, "checkmate")
        else:
            stdscr.addstr(19, 3, "stalemate")
        while True:
            c = stdscr.getch()
            if c == ord('q'):
                exit()

def remove_highlights(game_position):
    for x in range(8):
        for y in range(8):
            game_position.board[x][y].highlight = Highlights.NORMAL

def evaluate_position(game_position):
    score = 0
    for x in range(8):
        for y in range(8):
            match game_position.board[x][y].piece.piece:
                case Pieces.PAWN:
                    score += game_position.board[x][y].piece.colour * 1
                case Pieces.ROOK:
                    score += game_position.board[x][y].piece.colour * 5
                case Pieces.KNIGHT:
                    score += game_position.board[x][y].piece.colour * 3
                case Pieces.BISHOP:
                    score += game_position.board[x][y].piece.colour * 3
                case Pieces.QUEEN:
                    score += game_position.board[x][y].piece.colour * 9
    return score

def minimax(position, depth, alpha, beta, is_white):
    if depth == 0:
        return evaluate_position(position)
    if is_white:
        max_eval = -99999
        for move in get_all_legal_moves(position):
            position_copy = copy_position(position)
            move_piece(position_copy, move)
            swap_turn(position_copy)
            eval = minimax(position_copy, depth-1, alpha, beta, False)
            max_eval = max(max_eval, eval)
            alpha = max(alpha, eval)
            if beta <= alpha:
                break
        return max_eval
    else:
        min_eval = 99999
        for move in get_all_legal_moves(position):
            position_copy = copy_position(position)
            move_piece(position_copy, move)
            swap_turn(position_copy)
            eval = minimax(position_copy, depth-1, alpha, beta, True)
            min_eval = min(min_eval, eval)
            beta = min(beta, eval)
            if beta <= alpha:
                break
        return min_eval

def run_game(stdscr):
    game_position = Position(None, Colours.WHITE, True, True, True, True, -1)
    initialise_board(game_position)
    draw_board(stdscr, game_position)

    while True:
        check_game_over(stdscr, game_position)
        remove_highlights(game_position)
        #c = stdscr.getch()
        #if c == ord('q'):
        #    exit()

        legal_moves = get_all_legal_moves(game_position)
        evals = {}
        for move in legal_moves:
            position_copy = copy_position(game_position)
            move_piece(position_copy, move)
            swap_turn(position_copy)
            eval = minimax(position_copy, 2, -99999, 99999, position_copy.turn==Colours.WHITE)
            evals[move] = eval

        if game_position.turn == Colours.WHITE:
            best_eval = max(evals.values())
        else:
            best_eval = min(evals.values())
        best_moves = [move for move, eval in evals.items() if eval == best_eval]

        move_piece(game_position, choice(best_moves))
        swap_turn(game_position)

        stdscr.addstr(18, 3, " "*40)
        stdscr.addstr(18, 3, "eval: " + str(evaluate_position(game_position)))
        draw_board(stdscr, game_position)

def setup(stdscr):
    height, width = stdscr.getmaxyx()
    if height<20 or width<40:
        stdscr.addstr(0, 0, "terminal too small, zoom out")
        stdscr.refresh()
        sleep(1)
        exit()
    curs_set(0) # hide cursor
    init_pair(1, COLOR_RED, COLOR_BLACK)

def main(stdscr):
    setup(stdscr)
    draw_border(stdscr)
    run_game(stdscr)

if __name__ == "__main__":
    wrapper(main)
```


<br>

Perhaps copying the entire game_position struct is slowing it down and replacing it with an undo-move function would be an improvement...
