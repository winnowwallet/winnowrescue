# Reference data

Every expected value a test asserts comes from a file in a directory under
here, one directory per upstream source, each with a `SOURCE.md` naming the
URL, the upstream revision or tag, and the day it was copied. The files are
kept intact. Nothing here is regenerated with the code under test: when a
vector disagrees with the code, the code is wrong until a reading of the
standard says otherwise, and that reading goes in the commit message.
