import angr
import logging

logging.getLogger('angr').setLevel(logging.INFO)

p = angr.Project('liblibrary_card.so')

print_flag_addr = p.loader.find_symbol('print_flag').rebased_addr

print_flag = p.factory.callable(print_flag_addr)

print_flag(0x824, 0x82c, 0x82b)

print(print_flag.result_state.posix.stdout.concretize())