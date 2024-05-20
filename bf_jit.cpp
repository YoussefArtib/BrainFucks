#include <cstddef>
#include <cstdlib>
#include <ios>
#include <iostream>
#include <cstdint>
#include <fstream>
#include <stack>
#include <vector>
#include <cstring>
#include <cerrno>
#include <sys/mman.h>
#include <map>

#define MEM_SIZE 30000

typedef struct {
    char inst;
    int reps;
} Inst_Num;

std::vector<uint8_t> code;
std::map<size_t, size_t> loop_map;
unsigned char memory[MEM_SIZE] = {0};

void push_32bit_code(std::vector<uint8_t>& code, uint32_t some) {
    code.push_back((some >> (8*0)) & 0xFF);
    code.push_back((some >> (8*1)) & 0xFF);
    code.push_back((some >> (8*2)) & 0xFF);
    code.push_back((some >> (8*3)) & 0xFF);
}

void replace_32bit_code(std::vector<uint8_t>& code, size_t offset, uint32_t some) {
    code.at(offset + 0) = ((some >> (8*0)) & 0xFF);
    code.at(offset + 1) = ((some >> (8*1)) & 0xFF);
    code.at(offset + 2) = ((some >> (8*2)) & 0xFF);
    code.at(offset + 3) = ((some >> (8*3)) & 0xFF);
}

void push_64bit_code(std::vector<uint8_t>& code, uint64_t some) {
    push_32bit_code(code, (some >> (8*0)) & 0xFFFFFFFF);
    push_32bit_code(code, (some >> (8*4)) & 0xFFFFFFFF);
}

uint32_t compute_jmp(uint32_t next_inst, uint32_t where) {
    if (next_inst > where) {
        size_t rel32 = next_inst - where;
        return rel32;
    } else {
        size_t rel32 = where - next_inst;
        // NOTE: compute two's complement
        return 0xFFFFFFFF - static_cast<uint32_t>(rel32) + 0x1;
        // or you can just flip the bits and add 1;
        // return ~static_cast<uint32_t>(rel32) + 1;
    }
}

void jit_compile(std::vector<Inst_Num> instructions) {
    // mov r13, (uint64_t)memory
    code.insert(code.end(), {0x49, 0xBD});
    push_64bit_code(code, (uint64_t)memory);

    std::stack<size_t> open_parens;

    Inst_Num inst {};
    for (size_t ip = 0; ip < instructions.size(); ++ip) {
        inst = instructions[ip];
        switch (inst.inst) {
            case '>':
#if 1
                // add (r13), inst.reps
                code.insert(code.end(), {0x49, 0x81, 0xC5});
                push_32bit_code(code, inst.reps);
#else
                // FIXME: wrap around causes this error:
                // "ERROR: could not unmap memory: Invalid argument"
                // dp = ((dp + inst.reps) % MEM_SIZE + MEM_SIZE) % MEM_SIZE;
                // mov rax, r13
                code.insert(code.end(), {0x4C, 0x89, 0xE8});
                // add rax, static_cast<uint32>(inst.reps)
                code.insert(code.end(), {0x48, 0x05});
                push_32bit_code(code, static_cast<uint32_t>(inst.reps));
                // cqo
                code.insert(code.end(), {0x48, 0x99});
                // mov rbx, MEM_SIZE(30000)
                code.insert(code.end(), {0x48, 0xC7, 0xC3,
                                         0x30, 0x75, 0x00, 0x00});
                // mov rcx, (uint64_t)memory
                code.insert(code.end(), {0x48, 0xB9});
                push_64bit_code(code, (uint64_t)(memory));
                // add rbx, rcx
                code.insert(code.end(), {0x48, 0x01, 0xCB});
                // div rbx
                code.insert(code.end(), {0x48, 0xF7, 0xF3});
                // mov rax, rbx
                code.insert(code.end(), {0x48, 0x89, 0xD8});
                // add rax, rdx
                code.insert(code.end(), {0x48, 0x01, 0xD0});
                // cqo
                code.insert(code.end(), {0x48, 0x99});
                // div rbx
                code.insert(code.end(), {0x48, 0xF7, 0xF3});
                // mov r13, rdx
                code.insert(code.end(), {0x49, 0x89, 0xD5});
#endif
                break;
            case '<':
#if 1
                // sub r13, inst.reps
                code.insert(code.end(), {0x49, 0x81, 0xED});
                push_32bit_code(code, inst.reps);
#else
                // FIXME: wrap around causes this error:
                // "ERROR: could not unmap memory: Invalid argument"
                // dp = ((dp - inst.reps) % MEM_SIZE + MEM_SIZE) % MEM_SIZE;
                // mov rax, r13
                code.insert(code.end(), {0x4C, 0x89, 0xE8});
                // sub rax, static_cast<uint32>(inst.reps)
                code.insert(code.end(), {0x48, 0x2D});
                push_32bit_code(code, static_cast<uint32_t>(inst.reps));
                // cqo
                code.insert(code.end(), {0x48, 0x99});
                // mov rbx, MEM_SIZE(30000)
                code.insert(code.end(), {0x48, 0xC7, 0xC3,
                                         0x30, 0x75, 0x00, 0x00});
                // mov rcx, (uint64_t)memory
                code.insert(code.end(), {0x48, 0xB9});
                push_64bit_code(code, (uint64_t)memory);
                // add rbx, rcx
                code.insert(code.end(), {0x48, 0x01, 0xCB});
                // div rbx
                code.insert(code.end(), {0x48, 0xF7, 0xF3});
                // mov rax, rbx
                code.insert(code.end(), {0x48, 0x89, 0xD8});
                // add rax, rdx
                code.insert(code.end(), {0x48, 0x01, 0xD0});
                // cqo
                code.insert(code.end(), {0x48, 0x99});
                // div rbx
                code.insert(code.end(), {0x48, 0xF7, 0xF3});
                // mov r13, rdx
                code.insert(code.end(), {0x49, 0x89, 0xD5});
#endif
                break;
            case '+':
                // add byte [r13], inst.reps
                code.insert(code.end(), 
                     {0x41, 0x80, 0x45, 0x00, static_cast<uint8_t>(inst.reps)});
                break;
            case '-':
                // sub byte [r13], inst.reps
                code.insert(code.end(), 
                     {0x41, 0x80, 0x6D, 0x00, static_cast<uint8_t>(inst.reps)});
                break;
            case '.':
                // write syscall
                for (int i = 0; i < inst.reps; ++i) {
                    // mov rax, 1 (or better xor rax, rax; inc rax)
                    code.insert(code.end(), {0x48, 0x31, 0xC0, 0x48, 0xFF, 0xC0});
                    // mov rdi, 1 (stdout) (xor rdi, rdi; inc rdi)
                    code.insert(code.end(), {0x48, 0x31, 0xFF, 0x48, 0xFF, 0xC7});
                    // mov rsi, r13 (r64(memory))
                    code.insert(code.end(), {0x4C, 0x89, 0xEE});
                    // mov rdx, 1 (xor rdx, rdx; inc rdx)
                    code.insert(code.end(), {0x48, 0x31, 0xD2, 0x48, 0xFF, 0xC2});
                    // syscall
                    code.insert(code.end(), {0x0F, 0x05});
                }
                break;
            case ',':
                // read syscall
                for (int i = 0; i < inst.reps; ++i) {
                    // mov rax, 0 (or better xor rax, rax)
                    code.insert(code.end(), {0x48, 0x31, 0xC0});
                    // mov rdi, 0 (stdin) (xor rdi, rdi)
                    code.insert(code.end(), {0x48, 0x31, 0xFF});
                    // mov rsi, r13 (r64(memory))
                    code.insert(code.end(), {0x4C, 0x89, 0xEE});
                    // mov rdx, 1 (xor rdx, rdx; inc rdx)
                    code.insert(code.end(), {0x48, 0x31, 0xD2, 0x48, 0xFF, 0xC2});
                    // syscall
                    code.insert(code.end(), {0x0F, 0x05});
                }
                break;
            case '[':
                // cmp byte [r13 (r64(memory))], 0
                code.insert(code.end(), {0x41, 0x80, 0x7D, 0x00, 0x00});
                // jz rel32 (0x00000000)
                code.insert(code.end(), {0x0F, 0x84});
                push_32bit_code(code, 0x00000000);
                // NOTE: jumps are relative to the next instruction
                open_parens.push(code.size());
                break;
            case ']':
                size_t open_offset = open_parens.top();
                open_parens.pop();
                // cmp byte [r13 (r64(memory))], 0
                code.insert(code.end(), {0x41, 0x80, 0x7D, 0x00, 0x00});
                // jnz rel32 (0x00000000)
                code.insert(code.end(), {0x0F, 0x85});
                push_32bit_code(code, 0x00000000);
                // NOTE: jumps are relative to the next instruction
                uint32_t rel32 = compute_jmp(open_offset, code.size());
                replace_32bit_code(code, code.size() - 4, rel32);
                // Backpatching
                uint32_t open_paren_rel32 = compute_jmp(code.size(), open_offset);
                replace_32bit_code(code, open_offset - 4, open_paren_rel32);
                break;
        }
    }
    // ret;
    code.push_back(0xC3);
}

void jit_execute() {
    void* code_mem = mmap(0, code.size(), PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code_mem == (void*)-1) {

        std::cout << "ERROR: Could not allocate executable memory: "
                        << strerror(errno) << '\n';
        std::exit(1);
    }
    memcpy(code_mem, code.data(), code.size());

    if (mprotect(code_mem, code.size(), PROT_READ | PROT_EXEC) != 0) {
        std::cout << "ERROR: Could not change the memory protection: "
                        << strerror(errno) << '\n';
        std::exit(1);
    }

    using jitFunc = void (*)(void);
    ((jitFunc)code_mem)();

    if (code_mem != NULL) {
        if (munmap(code_mem, code.size()) < 0) {
            std::cout << "ERROR: Could not unmap memory: "
                    << strerror(errno) << '\n';
            std::exit(1);
        }
    }
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
    jit_compile(instructions);
    jit_execute();
    return 0;
}
