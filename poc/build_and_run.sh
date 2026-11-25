#!/usr/bin/env bash
# Builds and runs all three PoCs:
#   1. ZipSlipDataprocJobMainPoc    - vulnerable, cdap-runtime-ext-dataproc
#   2. ZipSlipFileLocalizerPoc      - vulnerable, cdap-kubernetes
#   3. ZipSlipControl_BundleJarUtil - control, the properly-protected sibling, cdap-common
#
# All three are byte-exact extractions (self-verified via cmp against a fresh clone of
# cdapio/cdap below) of the real methods, with zero logic changes - only the minimal
# surrounding class/imports needed to compile them standalone, since the full source files
# pull in unrelated heavy dependency chains (Hadoop/YARN, Twill's zookeeper/yarn modules,
# logback) that these specific methods never touch.
#
# Needs: network access to github.com + your distro's package archive (apt), and a JDK.

set -euo pipefail
CDAP_COMMIT="fb726c938e0668f1e8e30cb4734281033e86d968"   # cdapio/cdap @ develop, 2026-11-24
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$SCRIPT_DIR/build"

rm -rf "$WORKDIR" && mkdir -p "$WORKDIR"
cd "$WORKDIR"

if [ "$(id -u)" -eq 0 ]; then
  APT="apt-get"
else
  APT="sudo apt-get"
fi

echo "== Installing a JDK + slf4j (apt) =="
$APT update -qq
$APT install -y --no-install-recommends default-jdk-headless libslf4j-java >/dev/null

echo "== Cloning real cdapio/cdap @ $CDAP_COMMIT =="
git clone --filter=blob:none --no-checkout --depth 50 https://github.com/cdapio/cdap.git cdap
(cd cdap && git checkout "$CDAP_COMMIT")

echo "== Self-check: confirm the three PoC harnesses are byte-exact extractions of the live source at this commit =="
sed -n '221,258p' cdap/cdap-runtime-ext-dataproc/src/main/java/io/cdap/cdap/runtime/spi/runtimejob/DataprocJobMain.java \
  | cmp - "$SCRIPT_DIR/extracted_DataprocJobMain_unJar.txt"
sed -n '163,180p' cdap/cdap-kubernetes/src/main/java/io/cdap/cdap/k8s/runtime/FileLocalizer.java \
  | cmp - "$SCRIPT_DIR/extracted_FileLocalizer_expand.txt"
sed -n '309,369p' cdap/cdap-common/src/main/java/io/cdap/cdap/common/lang/jar/BundleJarUtil.java \
  | cmp - "$SCRIPT_DIR/extracted_BundleJarUtil_unJar_control.txt"
echo "(self-check passed - all three harnesses match the live source byte-for-byte at $CDAP_COMMIT)"

JARS="/usr/share/java/slf4j-api.jar"
mkdir -p out

echo
echo "== [1/3] VULNERABLE: DataprocJobMain.unJar() (cdap-runtime-ext-dataproc) =="
javac -nowarn -d out -cp "$JARS" "$SCRIPT_DIR/harness/ZipSlipDataprocJobMainPoc.java"
java -cp "out:$JARS" ZipSlipDataprocJobMainPoc

echo
echo "== [2/3] VULNERABLE: FileLocalizer.expand() (cdap-kubernetes) =="
javac -nowarn -d out -cp "$JARS" "$SCRIPT_DIR/harness/ZipSlipFileLocalizerPoc.java"
java -cp "out:$JARS" ZipSlipFileLocalizerPoc

echo
echo "== [3/3] CONTROL: BundleJarUtil.unJar() (cdap-common) - properly protected sibling =="
javac -nowarn -d out "$SCRIPT_DIR/harness/ZipSlipControl_BundleJarUtil.java"
java -cp out ZipSlipControl_BundleJarUtil
