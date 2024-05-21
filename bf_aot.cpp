#include <cstddef>
#include <cstdlib>
#include <ios>
#include <iostream>
#include <fstream>
#include <stack>
#include <vector>
#include <cstring>
#include <cerrno>
#include <map>
#include <sys/mman.h>


typedef struct {
    char inst;
    int reps;
} Inst_Num;

std::map<size_t, size_t> loop_map;

void aot_compile(std::vector<Inst_Num> instructions) {
    std::ofstream asmfile {"output.asm"};
    asmfile << "BITS 64\n"; 
    asmfile << "%define STDIN 0\n";
    asmfile << "%define STDOUT 1\n";
    asmfile << "%define READ_SYS 0\n";
    asmfile << "%define WRITE_SYS 1\n";
    asmfile << "%define EXIT_SYS 60\n";
    asmfile << "%define MEM_SIZE 30000\n";
    asmfile << '\n';
    asmfile << "global _start\n"; 
    asmfile << "section .text\n";
    asmfile << "_start:\n"; 
    asmfile << "    mov r13, memory\n";

    Inst_Num inst {};
    for (size_t ip = 0; ip < instructions.size(); ++ip) {
        inst = instructions[ip];
        switch (inst.inst) {
            case '>':
#if 1
                // add r13, inst.reps
                asmfile << "    add r13, " << inst.reps << "\n";
#else
                // dp = ((dp + inst.reps) % MEM_SIZE + MEM_SIZE) % MEM_SIZE;
                asmfile << "    mov rax, r13\n";
                asmfile << "    add rax, " << inst.reps <<"\n";
                asmfile << "    cqo\n";
                asmfile << "    mov rbx, MEM_SIZE\n";
                asmfile << "    add rbx, memory\n";
                asmfile << "    div rbx\n";
                asmfile << "    mov rax, rbx\n";
                asmfile << "    add rax, rdx\n";
                asmfile << "    cqo\n";
                asmfile << "    div rbx\n";
                asmfile << "    mov r13, rdx\n";
#endif
                break;
            case '<':
#if 1
                // sub r13, inst.reps
                asmfile << "    sub r13, " << inst.reps << "\n";
#else
                // dp = ((dp - inst.reps) % MEM_SIZE + MEM_SIZE) % MEM_SIZE;
                asmfile << "    mov rax, r13\n";
                asmfile << "    sub rax, " << inst.reps <<"\n";
                asmfile << "    cqo\n";
                asmfile << "    mov rbx, MEM_SIZE\n";
                asmfile << "    add rbx, memory\n";
                asmfile << "    div rbx\n";
                asmfile << "    mov rax, rbx\n";
                asmfile << "    add rax, rdx\n";
                asmfile << "    cqo\n";
                asmfile << "    div rbx\n";
                asmfile << "    mov r13, rdx\n";
#endif
                break;
            case '+':
                // add byte [r13], inst.reps
                asmfile << "    add byte [r13], " << inst.reps << "\n";
                break;
            case '-':
                // sub byte [r13], inst.reps
                asmfile << "    sub byte [r13], " << inst.reps << "\n";
                break;
            case '.':
                for (int i = 0; i < inst.reps; ++i) {
                    // write syscall
                    asmfile << "    ;write\n";
                    // mov rax, 1 (or better xor rax, rax; inc rax)
                    asmfile << "    mov rax, WRITE_SYS\n";
                    // mov rdi, 1 (stdout) (xor rdi, rdi; inc rdi)
                    asmfile << "    mov rdi, STDOUT\n";
                    // mov rsi, r13
                    asmfile << "    mov rsi, r13\n";
                    // mov rdx, 1 (xor rdx, rdx; inc rdx)
                    asmfile << "    mov rdx, 1\n";
                    // syscall
                    asmfile << "    syscall\n";
                }
                break;
            case ',':
                for (int i = 0; i < inst.reps; ++i) {
                    // read syscall
                    asmfile << "    ;read\n";
                    // mov rax, 0 (or better xor rax, rax)
                    asmfile << "    mov rax, READ_SYS\n";
                    // mov rdi, 0 (stdin) (xor rdi, rdi)
                    asmfile << "    mov rdi, STDIN\n";
                    // mov rsi, r13
                    asmfile << "    mov rsi, r13\n";
                    // mov rdx, 1 or (xor rdx, rdx; inc rdx)
                    asmfile << "    mov rdx, 1\n";
                    // syscall
                    asmfile << "    syscall\n";
                }
                break;
            case '[':
                // cmp byte [r13], 0
                asmfile << "    cmp byte [r13], 0\n";
                // jz rel32 (.after_cbXX)
                asmfile << "    jz .after_cb" << loop_map.find(ip)->second << '\n' ;
                asmfile << ".after_ob" << ip << ":\n";
                break;
            case ']':
                // cmp byte [r13], 0
                asmfile << "    cmp byte [r13], 0\n";
                // jnz rel32 (.after_obXX)
                asmfile << "    jnz .after_ob" << loop_map.find(ip)->second << '\n';
                asmfile << ".after_cb" << ip << ":\n";
                break;
            default:
                std::cout << "Unreachable";
        }
    }
    asmfile << "   ; exit(0)\n";
    asmfile << "   mov rax, EXIT_SYS\n";
    asmfile << "   mov rdi, 0\n";
    asmfile << "   syscall\n";

    asmfile << '\n';
    asmfile << "section .data\n";
    asmfile << "    memory: times MEM_SIZE db 0\n";

    asmfile.close();
    // TODO:
    // try running the following commands from here
    // ```console     
    // $ nasm -f elf64 outuput.asm -o output.o
    // $ ld -o output output.o
    // ```
    // maybe we can use the "system(const char *command);" function
}


// TODO: wrap around if the count of instructions ("+", "-") > 256.
std::vector<Inst_Num> parse_bf(const char* input, bool optimize) {

    std::vector<Inst_Num> instructions {};
    std::stack<size_t> open_stack;
    std::ifstream file {input};
    if (!file) {
        std::cerr << "Error: Could not open file " << input << '\n';
        std::exit(1);
    }

    std::string bf_insts = "><+-.,[]";
    char ch {};
    char last_char {};
    while (file.get(ch)) {
        if (bf_insts.find(ch) != std::string::npos) {
            if (ch == '[') {
                open_stack.push(instructions.size());
            }
            if (ch == ']') {

                int open = open_stack.top();
                loop_map.insert({open, instructions.size()});
                loop_map.insert({instructions.size(), open});
                open_stack.pop();
            }
            if (optimize) {
                if (ch == last_char) {
                    if (ch != '[' && ch != ']') {
                        instructions[instructions.size() - 1].reps += 1;
                    } else {
                        instructions.push_back({.inst = ch, .reps = 1});
                    }
                } else {
                    instructions.push_back({.inst = ch, .reps = 1});
                }
                last_char = ch;
            } else {
                instructions.push_back({.inst = ch, .reps = 1});
            }
        }
    }
    return instructions;
}

void shift_args(int* argc, char*** argv) {
    *argc = *argc - 1;
    *argv = *argv + 1;
}

int main(int argc, char** argv) {
    if (argc <= 1) {
        std::cout << "Usage: " << *argv << " [--optimize] <input.bf>\n";
        std::cout << "Supported flags:\n";
        std::cout << "    --optimize: Enable optimization\n";
        return 1;
    }
    shift_args(&argc, &argv);

    bool optimize = false;
    if (strcmp(*argv, "--optimize") == 0) {
        optimize = true;
        (void) optimize;
        shift_args(&argc, &argv);
    }

    std::vector<Inst_Num> instructions = parse_bf(*argv, optimize);
    aot_compile(instructions);
    return 0;
}
