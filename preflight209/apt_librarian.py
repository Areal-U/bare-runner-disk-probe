"""Extra immutable Ubuntu objects for the fixed Chromium package transaction."""

# (pool path, size, SHA256, immutable Ubuntu Launchpad Librarian object).
# The full 809-row signed plan is verified before acquisition. These eight
# byte pins also bind the fallback independently of the three ordinary hosts.
LIBRARIAN = {
    "pool/main/e/elfutils/elfutils_0.186-1ubuntu0.1_amd64.deb":
        (500084, "877197342235f3a253fe6963738cfabded93c6ebe817978d100dbb6ff3bb810d", 782401553),
    "pool/main/e/elfutils/libasm1_0.186-1ubuntu0.1_amd64.deb":
        (15578, "8721bf4f88546d84c8ae46d31a37bd78a295a5a8df5cab668308928e5a37ce9d", 782401554),
    "pool/main/e/elfutils/libdw1_0.186-1ubuntu0.1_amd64.deb":
        (250724, "487120e8e4468844a1bd024c3684e97dbe831fbaa04b975a337e8482370c4e17", 782401556),
    "pool/main/e/elfutils/libelf-dev_0.186-1ubuntu0.1_amd64.deb":
        (64406, "c4aeee4339737e2177426dba4b548a55d16e54a3a63bc34e783b92bba3aa49b1", 782401550),
    "pool/main/e/elfutils/libelf1_0.186-1ubuntu0.1_amd64.deb":
        (51140, "2cc781614b045b450a1e073ee3b0902f393ee58ede1d2ea4526ad805fcccf538", 782401557),
    "pool/main/e/elfutils/libelf1_0.186-1ubuntu0.1_i386.deb":
        (55424, "d2afb45a01c2d7cfa7e956741cc0e2502bf5a0b823422d63d1b65b47ad714259", 782401579),
    "pool/main/e/expat/libexpat1-dev_2.4.7-1ubuntu0.9_amd64.deb":
        (151246, "5ed152003cdb6e840985d41a5fbc72a72dfe2e92e187d57b66052de3ea8ee2cd", 877865685),
    "pool/main/e/expat/libexpat1_2.4.7-1ubuntu0.9_i386.deb":
        (98396, "9318c7c4cb706b3db32f31d4236be469f9e2f0533b4a003146fac7dc9870bc64", 877864502),
}


def librarian_path(path, record):
    pin = LIBRARIAN.get(path)
    if pin is None:
        return None
    package, version, arch, size, digest = record
    filename = path.rsplit("/", 1)[1]
    if (filename != f"{package}_{version}_{arch}.deb" or (size, digest) != pin[:2]):
        raise ValueError(f"Launchpad pin differs from signed package metadata: {path}")
    return f"/{pin[2]}/{filename}"
