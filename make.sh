#!/bin/bash

if [ ! -d  "./build" ]; then
    mkdir ./build
fi

if [ "$1" = "--jit" ] || [ "$1" = "--all" ] || [ $# = 0 ]; then
    g++ -O3 -Wall -Wextra -Werror bf_jit.cpp -o ./build/jit
fi

if [ "$1" = "--aot" ] || [ "$1" = "--all" ] || [ $# = 0 ]; then
    g++ -O3 -Wall -Wextra -Werror bf_aot.cpp -o ./build/aot
fi

if [ "$1" = "--interp" ] || [ "$1" = "--all" ] || [ $# = 0 ]; then
    g++ -O3 -Wall -Wextra -Werror bf_interp.cpp -o ./build/interp
fi
