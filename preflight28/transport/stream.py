"""Write a compressed stream without allowing a candidate past its physical cap."""
import os
from pathlib import Path
import sys

class CompressedSizeExceeded(ValueError):
    pass


def store(reader, destination, cap):
    count = 0
    with destination.open("xb") as output:
        while block := reader.read(1024**2):
            count += len(block)
            if count > cap:
                raise CompressedSizeExceeded("Compressed checkpoint exceeds the fixed limit")
            output.write(block)
        if not count:
            raise ValueError("Empty checkpoint")
        output.flush()
        os.fsync(output.fileno())

if __name__ == "__main__":
    store(sys.stdin.buffer, Path(sys.argv[1]), 7 * 1024**3 // 2)
