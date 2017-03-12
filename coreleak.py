import array

from curses.ascii import isprint
from itertools import groupby

STATUS_UNKNOWN, \
        STATUS_INDIRECTLY_LOST,\
        STATUS_DIRECTLY_LOST,\
        STATUS_INDIRECTLY_REACHABLE,\
        STATUS_DIRECTLY_REACHABLE,\
        STATUS_ROOT = range(6)

status_names = {STATUS_UNKNOWN: 'unknown',
                STATUS_INDIRECTLY_LOST: 'indirectly-lost',
                STATUS_DIRECTLY_LOST: 'directly-lost',
                STATUS_INDIRECTLY_REACHABLE: 'indirectly-reachable',
                STATUS_DIRECTLY_REACHABLE: 'directly-reachable',
                STATUS_ROOT: 'root'}

class Block(object):
    def __init__(self, addr, data, status=STATUS_UNKNOWN):
        self.addr = addr
        self.raw_data = data
        try:
            self.data = array.array('L', data)
        except:
            self.data = array.array('L', bytes(data))
        self.size = len(self.data) * self.data.itemsize
        self.status = status
        self.references = []

    def __repr__(self):
        return '%u@%#08x' % (self.size, self.addr)

    def get_status(self, lookup=None):
        if self.status != STATUS_UNKNOWN or lookup == self:
            return self.status

        if not lookup:
            lookup = self

        if not self.references:
            self.status = STATUS_DIRECTLY_LOST
        else:
            refstatus = max(s.get_status(lookup) for s in self.references)
            if refstatus == STATUS_UNKNOWN:
                self.status = refstatus
            else:
                self.status = refstatus - 1

        return self.status

class CoreLeak(object):
    def __init__(self):
        self.blocks = []
    
    def add_block(self, block):
        self.blocks.append(block)

    def sum(self, status):
        blocks = [b for b in self.blocks if b.get_status() == status]

    def dump(self, addr, data, length=16):
        out = []
        for i in range(0, len(data), length):
            s = data[i : i + length]
            raw = ' '.join(['%02x' % ord(x) for x in s])
            text = ''.join([chr(ord(x)) if isprint(ord(x)) else '.'  for x in s])
            out.append('%#08x: %-*s %s' % (addr + i, length * 3, raw, text))

        return out

    def analyze(self, dump=False):
        for block in self.blocks:
            block.references = [b for b in self.blocks if block.addr in b.data]

        print('HEAP SUMMARY:') 
        blocks = [b for b in self.blocks if b.get_status() != STATUS_ROOT]
        print('    in use at exit: %u bytes in %u blocks' %
                (sum([b.size for b in blocks]), len(blocks)))
        print('')

        sizekey = lambda b:b.size

        blocks = [b for b in self.blocks if b.get_status() == STATUS_DIRECTLY_LOST]
        blocks = sorted(blocks, key=sizekey)
        for sz, group in groupby(blocks, key=sizekey):
            group = list(group)
            print('%u bytes in %u blocks of size %u are definitely lost' %
                (sum([b.size for b in group]), len(group), sz))

            if dump:
                for b in group:
                    print(b)
                    print('\n'.join(self.dump(b.addr, b.raw_data)))
                print('')

        if blocks and not dump:
            print('')

        blocks = [b for b in self.blocks if b.get_status() == STATUS_INDIRECTLY_LOST]
        blocks = sorted(blocks, key=sizekey)
        for sz, group in groupby(blocks, key=sizekey):
            group = list(group)
            print('%u bytes in %u blocks of size %u are definitely lost (indirectly)' %
                (sum([b.size for b in group]), len(group), sz))

            if dump:
                for b in group:
                    print(b)
                    print('\n'.join(self.dump(b.addr, b.raw_data)))
                print('')

        if blocks and not dump:
            print('')

        print('LEAK SUMMARY:') 

        blocks = [b for b in self.blocks if b.get_status() == STATUS_DIRECTLY_LOST]
        print('   definitely lost: %u bytes in %u blocks' %
                (sum([b.size for b in blocks]), len(blocks)))

        blocks = [b for b in self.blocks if b.get_status() == STATUS_INDIRECTLY_LOST]
        print('   indirectly lost: %u bytes in %u blocks' %
                (sum([b.size for b in blocks]), len(blocks)))

        blocks = [b for b in self.blocks
                  if b.get_status() == STATUS_INDIRECTLY_REACHABLE or
                  b.get_status() == STATUS_DIRECTLY_REACHABLE]
        print('   still reachable: %u bytes in %u blocks' %
                (sum([b.size for b in blocks]), len(blocks)))

# if __name__ == '__main__':
#     coreleak = CoreLeak()
#     coreleak.blocks.append(Block(0x10000000, '\x00\x00\x00\x20\x00\x00\x00\x40',
#                                 STATUS_ROOT))
#     coreleak.blocks.append(Block(0x20000000, '\x00\x00\x00\x30'))
#     coreleak.blocks.append(Block(0x30000000, '\x00\x00\x00\x00'))
#     coreleak.blocks.append(Block(0x40000000, '\x00\x00\x00\x00'))
#     coreleak.blocks.append(Block(0x50000000, '\x00\x00\x00\x60'))
#     coreleak.blocks.append(Block(0x60000000, '\x00\x00\x00\x00'))
#     coreleak.analyze()
 
import gdb
import re
import libheap

libheap.frontend.printutils.colors_enabled = False

class LeaksCommand(gdb.Command):
    """Print memory leaks.
Use of the 'dump' qualifier also prints a hex dump of leaked buffers.
Use of the 'no-regs' qualifier prevents checking thread registers for references.
Use of the 'no-stack' qualifier prevents checking thread stacks for references."""

    def __init__ (self):
        super (LeaksCommand, self).__init__ ("leaks",
                         gdb.COMMAND_DATA, gdb.COMPLETE_NONE, False)

    def parse_heapls(self, coreleak, output):
        inferior = gdb.selected_inferior()
        for line in output.split('\n'):
            if not line.startswith('chunk') or 'inuse' not in line:
                continue

            _, addr, size, _ = re.split(' +', line)

            addr = int(addr, 16)
            size = int(size, 16)

            addr += 16
            size -= 16

            block = Block(addr, inferior.read_memory(addr, size))
            coreleak.blocks.append(block)

    def add_static_data(self, coreleak):
        inferior = gdb.selected_inferior()
        output = gdb.execute('maintenance info sections ALLOBJ ALLOC', to_string=True)
        seen = []
        sizeofptr = gdb.parse_and_eval('sizeof(void *)')
        for line in output.split('\n'):
            if line.startswith('Core'):
                break

            if 'ALLOC' not in line:
                continue

            # Not sure if we need READONLY sections
            if 'READONLY' in line:
                continue

            m = re.search('(0x[a-f0-9]+)->(0x[a-f0-9]+)', line)
            start, end = m.groups()

            start = int(start, 16)
            end = int(end, 16)
            size = end - start

            # Is this correct?
            size = size & ~(sizeofptr - 1)

            if start in seen:
                continue

            seen.append(start)

            block = Block(start, inferior.read_memory(start, size), STATUS_ROOT)
            coreleak.blocks.append(block)

    def invoke(self, arg, from_tty):
        coreleak = CoreLeak()

        argv = gdb.string_to_argv(arg)

        checkstacks = 'no-stack' not in argv
        checkregs = 'no-regs' not in argv

        inferior = gdb.selected_inferior()
        for thread in inferior.threads():
            thread.switch()

            if checkstacks:
                output = gdb.execute('thread', to_string=True)
                m = re.search('Thread (0x[^ ]+)', output)
                pthread = int(m.groups()[0], 16)
                stackblock = gdb.parse_and_eval('(*(struct pthread *) %#x)->stackblock' % pthread)
                if stackblock:
                    stacksize = gdb.parse_and_eval('(*(struct pthread *) %#x)->stackblock_size' % pthread)
                    stacktop = stackblock + stacksize
                else:
                    stacktop = gdb.parse_and_eval('__libc_stack_end')

                sp = gdb.parse_and_eval('$sp')
                block = Block(sp, inferior.read_memory(sp, stacktop - sp), STATUS_ROOT)
                coreleak.blocks.append(block)

            if checkregs:
                output = gdb.execute('info registers', to_string=True)
                regs = [int(r, 16) for r in re.findall('(0x[a-f0-9]+)', output)]
                coreleak.blocks.append(Block(0x0, regs, STATUS_ROOT))

        output = gdb.execute('heap', to_string=True)
        arenas = [int(r, 16) for r in re.findall('(0x[a-f0-9]+)', output)]
        for arena in arenas:
            output = gdb.execute('heapls %#x' % arena, to_string=True)
            self.parse_heapls(coreleak, output)

        self.add_static_data(coreleak)

        coreleak.analyze(dump='dump' in argv)

LeaksCommand()
