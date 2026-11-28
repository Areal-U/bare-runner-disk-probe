#!/usr/bin/python3 -I
"""Pinned cache client extraction hook. Only named regular packet members reach disk."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

# -I excludes the current working directory and all environment module paths.
sys.path.insert(0, str(Path(os.environ['GITHUB_WORKSPACE']).resolve()/'preflight209'))
import checkpoint_packets as p


class Member(tarfile.TarInfo):
    def _proc_member(self, archive):
        p.REQUIRE(self.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.XHDTYPE),
                  'Unsupported cache tar member type')
        if self.type == tarfile.XHDTYPE:
            p.REQUIRE(0 < self.size <= 4096, 'Unbounded cache tar extension header')
        return super()._proc_member(archive)


def unpack(source, kind):
    expected = p.BOUNDS[kind]
    folder = p.folder(kind)
    p.REQUIRE(folder.resolve()==folder and folder.is_dir() and not list(folder.iterdir()),
              'Restore staging directory must be empty')
    ceiling = sum(expected.values())+128*1024
    seen = set()
    with tempfile.TemporaryFile(dir=os.environ['RUNNER_TEMP']) as raw:
        proc = subprocess.Popen(['/usr/bin/zstd','-qd','--memory=128MB','-c','--',source],stdout=subprocess.PIPE)
        try:
            while block:=proc.stdout.read(1024**2):
                p.REQUIRE(raw.tell()+len(block)<=ceiling, 'Expanded cache archive exceeds limit')
                raw.write(block)
            p.REQUIRE(proc.wait(timeout=10)==0, 'Corrupt or interrupted zstd cache archive')
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()
        raw.seek(0)
        with tarfile.open(fileobj=raw,mode='r:',tarinfo=Member) as archive:
            for member in archive:
                p.REQUIRE(member.name not in seen, 'Duplicate name in cache archive')
                seen.add(member.name)
                if member.isdir():
                    p.REQUIRE(member.name==folder.name and member.size==0, 'Unexpected directory in cache archive')
                    continue
                name = Path(member.name).name
                p.REQUIRE(member.type in (tarfile.REGTYPE,tarfile.AREGTYPE) and not member.sparse and
                          name in expected and member.name==f'{folder.name}/{name}' and 0<=member.size<=expected[name],
                          'Unrecognized cache member, linked file, or byte limit')
                with (folder/name).open('xb') as dest:
                    shutil.copyfileobj(archive.extractfile(member),dest,1024**2)
                    p.REQUIRE(dest.tell()==member.size, 'Incomplete archive member')
            raw.seek(archive.offset)
            tail = raw.read(65537)
            p.REQUIRE(1024<=len(tail)<=65536 and not any(tail),'Unexpected cache archive trailer')
        p.checked_files(kind,folder)


if __name__=='__main__':
    argv = sys.argv[1:]
    p.REQUIRE(len(argv)==7 and argv[0]=='-xf' and argv[2:]==['-P','-C',os.environ['GITHUB_WORKSPACE'],
              '--use-compress-program','unzstd'], 'Unrecognized pinned cache tar invocation')
    archive = Path(argv[1])
    p.REQUIRE(archive.name=='cache.tzst' and archive.is_relative_to(Path(os.environ['RUNNER_TEMP'])) and
              p.regular(archive,p.archive_bound(p.PACKET_BYTES))>0, 'Unexpected compressed cache reply')
    unpack(archive,os.environ['R209_PACKET_KIND'])
