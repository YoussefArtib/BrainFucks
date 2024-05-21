# BrainFucks:
An interpreter, a JIT compiler and an AOT compiler for [BrainFuck](https://en.wikipedia.org/wiki/Brainfuck).

# Prerequisite:
In case you wanna run the AOT you need to install [nasm](https://www.nasm.us/).

# Quick start:
NB: not passing any argument to ./make.sh will build everthing.
```console
$ ./make.sh [--jit | --aot | --interp | --all]
```
Also, the AOT produces a .asm file, run the following commands to make an executable:
```console
$ nasm -f elf64 outuput.asm -o output.o
$ ld -o output output.o
```
