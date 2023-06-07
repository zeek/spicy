#! /bin/sh
# @TEST-EXEC: /bin/sh %INPUT
#
# Checks that (1) we don't use bash anywhere, and (2) our sh scripts don't
# use bashisms.

self=$(cd $(dirname $0) && pwd)/$(basename $0)

if [ -z "${DIST}" ]; then
    echo "DIST not set" >&2
    exit 1
fi

if [ -z "${SCRIPTS}" ]; then
    echo "SCRIPTS not set" >&2
    exit 1
fi

cd ${DIST}

${SCRIPTS}/3rdparty/checkbashisms.pl ${self} >output 2>&1

# Find any direct use of bash.
dirs="hilti spicy scripts tests ci"

# Whitelist: ci/run-ci - We use bash for this one.
find ${dirs} -type f | grep -v 3rdparty | grep -v '\.tmp/' | grep -v bashisms.sh | grep -v ci/run-ci | while read i; do
    grep -E '\<bash\>' $i | awk "{ print \"found bash in $i: \" \$0}" >>output 2>&1
    if head -1 $i | grep -E -q '#!.*\<sh\>'; then
       ${SCRIPTS}/3rdparty/checkbashisms.pl $i >>output 2>&1
    fi
done

cat output >&2
test '!' -s output
