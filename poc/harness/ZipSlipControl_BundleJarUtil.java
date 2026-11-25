import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.nio.file.CopyOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Control: the SAME malicious zip payload used against DataprocJobMain.unJar() and
 * FileLocalizer.expand(), run instead against the real, unmodified, properly-protected sibling
 * BundleJarUtil.unJar() (cdap-common/.../lang/jar/BundleJarUtil.java, same commit, byte-exact
 * extraction of lines 309-369, self-verified via cmp - see
 * extracted_BundleJarUtil_unJar_control.txt). Confirms the vulnerable methods' behavior is a
 * genuine, specific omission - not something inherent to how CDAP generally handles zip
 * extraction - by showing the one real containment check (output.normalize() +
 * startsWith(targetPath)) correctly rejects the identical attack.
 */
public class ZipSlipControl_BundleJarUtil {

  // ===== BEGIN byte-exact extraction from BundleJarUtil.java lines 309-369 =====

  private static File unJar(File jarFile, File destinationFolder, Predicate<String> nameFilter,
      CopyOption... copyOptions)
      throws IOException {
    try (ZipInputStream zipIn = new ZipInputStream(
        new BufferedInputStream(new FileInputStream(jarFile)))) {
      unJar(zipIn, destinationFolder, nameFilter, copyOptions);
    }
    return destinationFolder;
  }

  private static void unJar(ZipInputStream input, File targetDirectory,
                            Predicate<String> nameFilter,
                            CopyOption... copyOptions)
    throws IOException {

    Path targetPath = targetDirectory.toPath().normalize();
    boolean isSuccess = false;
    boolean isTargetDirectoryNewlyCreated = false;

    try {
      // Check if the directory exists before trying to create it
      if (!Files.exists(targetPath)) {
        Files.createDirectories(targetPath);
        isTargetDirectoryNewlyCreated = true;
      }

      ZipEntry entry;
      while ((entry = input.getNextEntry()) != null) {
        String entryName = entry.getName();

        if (!nameFilter.test(entryName)) {
          continue;
        }

        Path output = targetPath.resolve(entryName).normalize();

        if (!output.startsWith(targetPath)) {
          throw new IllegalArgumentException("Illegal path detected for Jar Entry : " + entryName + ". This will try to"
                                               + " write outside the target directory, which is not allowed.");
        }

        if (entry.isDirectory()) {
          Files.createDirectories(output);
        } else {
          Files.createDirectories(output.getParent());
          Files.copy(input, output, copyOptions);
        }
        input.closeEntry();
      }
      isSuccess = true;
    } finally {
      // Cleanup logic: Only delete if not successful AND we created the directory
      if (!isSuccess && isTargetDirectoryNewlyCreated && Files.exists(targetPath)) {
        try (Stream<Path> paths = Files.walk(targetPath)) {
          paths.sorted(Comparator.reverseOrder())
            .map(Path::toFile)
            .forEach(File::delete);
        }
      }
    }
  }

  // ===== END byte-exact extraction =====

  public static void main(String[] args) throws Exception {
    Path sandbox = Files.createTempDirectory("bundlejarutil-control-poc");
    Path targetDir = sandbox.resolve("extraction-target");
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
      zos.write("should never be written\n".getBytes("UTF-8"));
      zos.closeEntry();
    }

    System.out.println("Same malicious entry name as the other two PoCs: " + entryName);
    System.out.println("Running it through the real BundleJarUtil.unJar()...");
    try {
      unJar(maliciousArchive.toFile(), targetDir.toFile(), name -> true);
      System.out.println("Did NOT throw - unexpected.");
    } catch (IllegalArgumentException e) {
      System.out.println();
      System.out.println("CORRECTLY REJECTED: " + e.getMessage());
      System.out.println("Exists? " + Files.exists(victimMarker));
      System.out.println();
      System.out.println("CONTROL CONFIRMED: the real, unmodified, properly-protected sibling");
      System.out.println("BundleJarUtil.unJar() detects and rejects the identical payload that");
      System.out.println("succeeds against DataprocJobMain.unJar() and FileLocalizer.expand().");
    }
  }
}
