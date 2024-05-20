#include <cstring>
#include <ios>
#include <iostream>
#include <fstream>
#include <stack>
#include <map>
#include <vector>

#define MEM_SIZE 30000

std::vector<unsigned char> code;
std::map<size_t, size_t> loop_map;

typedef struct {
    char inst;
    int reps;
} Inst_Num;

void interpreter(std::vector<Inst_Num> instructions) {
    unsigned char memory[MEM_SIZE] = {0};
    size_t dp = 0;
    Inst_Num inst;
    for (size_t ip = 0; ip < instructions.size();) {
        inst = instructions[ip];
        switch (inst.inst) {
            case '>': {
                // dp = dp + inst.reps;
                dp = ((dp + inst.reps) % MEM_SIZE + MEM_SIZE) % MEM_SIZE;
            }
                break;
            case '<': {
                // dp = dp - inst.reps;
                dp = ((dp - inst.reps) % MEM_SIZE + MEM_SIZE) % MEM_SIZE;
            }
                break;
            case '+': {
                // TODO: wrap around.
                // memory[dp]= ((memory[dp] + inst.reps) % 256 + 256) % 256;
                memory[dp] += inst.reps;
                }
                break;
            case '-': {
                // TODO: wrap around.
                // memory[dp]= ((memory[dp] - inst.reps) % 256 + 256) % 256;
                memory[dp] -= inst.reps;
                }
                break;
            case '.': {
                for (int i = 0; i < inst.reps; ++i) {
                    std::cout << memory[dp];
                }
            }
                break;
            case ',': {
                for (int i = 0; i < inst.reps; ++i) {
                    std::cin >> memory[dp];
                }
            }
                break;
            case '[':
                if (memory[dp] == 0) {
                    ip = loop_map.find(ip)->second;
                }
                break;
            case ']':
                if (memory[dp] != 0) {
                    ip = loop_map.find(ip)->second;
                }
                break;
            default:
                std::cout << "Unreachable";
        }
        ip += 1;
    }
}

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
    interpreter(instructions);
    return 0;
}
