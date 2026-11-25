# cdap: missing zip-slip protection in DataprocJobMain.unJar() and FileLocalizer.expand() allows arbitrary file write outside the intended extraction directory

## Summary

CDAP extracts "archive"-type program resources (plugin JARs, bundled dependencies, and other localized files shipped to remote execution environments) using `ZipInputStream` in two separate locations that both omit the standard zip-slip containment check present in a third, sibling function in the same codebase:

| Function | File | Module | Protection |
|---|---|---|---|
| `unJar(Path)` | `DataprocJobMain.java` | `cdap-runtime-ext-dataproc` | **MISSING** |
| `expand(URI, InputStream, Path)` | `FileLocalizer.java` | `cdap-kubernetes` | **MISSING** |
| `unJar(ZipInputStream, File, Predicate, CopyOption...)` | `BundleJarUtil.java` | `cdap-common` | Present — `normalize()` + `startsWith()` guard |

Both unprotected functions unconditionally resolve each zip entry's name against the target directory via `targetDir.resolve(entry.getName())` and write to the resulting path, with no `.normalize()` and no `startsWith(targetDir)` containment check. A zip entry named `../../some/path` writes `some/path` relative to the parent of `targetDir` — arbitrary file write to any path accessible to the running process.

The protected sibling (`BundleJarUtil.unJar()`) does exactly what the other two omit, and throws `IllegalArgumentException("Illegal path detected for Jar Entry ...")` before writing anything. Its guard was evidently written to protect against this exact class of attack; the same guard simply was not applied to the other two extraction functions.

## Bug location

**Vulnerable (no protection):**

`DataprocJobMain.unJar()` — lines 235–258:
https://github.com/cdapio/cdap/blob/fb726c938e0668f1e8e30cb4734281033e86d968/cdap-runtime-ext-dataproc/src/main/java/io/cdap/cdap/runtime/spi/runtimejob/DataprocJobMain.java#L235-L258

```java
// DataprocJobMain.java (VULNERABLE — no normalize(), no startsWith())
Path output = targetDir.resolve(entry.getName());
// no containment check — writes directly to resolved path
Files.copy(zipIn, output);
```

`FileLocalizer.expand()` — lines 163–180:
https://github.com/cdapio/cdap/blob/fb726c938e0668f1e8e30cb4734281033e86d968/cdap-kubernetes/src/main/java/io/cdap/cdap/k8s/runtime/FileLocalizer.java#L163-L180

```java
// FileLocalizer.java (VULNERABLE — no normalize(), no startsWith())
Path outputPath = targetPath.resolve(entry.getName());
// no containment check — writes directly to resolved path
Files.copy(is, outputPath, StandardCopyOption.REPLACE_EXISTING);
```

**Protected (correctly guarded, included as the control):**

`BundleJarUtil.unJar()` — lines 341–348:
https://github.com/cdapio/cdap/blob/fb726c938e0668f1e8e30cb4734281033e86d968/cdap-common/src/main/java/io/cdap/cdap/common/lang/jar/BundleJarUtil.java#L341-L348

```java
// BundleJarUtil.java (PROTECTED — the guard that is missing above)
Path output = targetPath.resolve(entryName).normalize();
if (!output.startsWith(targetPath)) {
  throw new IllegalArgumentException("Illegal path detected for Jar Entry : " + entryName
      + ". This will try to write outside the target directory, which is not allowed.");
}
```

Verified against commit `fb726c938e0668f1e8e30cb4734281033e86d968` (`develop`, 2026-11-24, current HEAD at time of writing).

## Root cause

The same extraction logic was implemented in three places without centralizing or sharing the containment check. `BundleJarUtil.unJar()` added the check (and even includes an explicit error message noting the write-outside-directory risk), but that check was never back-ported to `DataprocJobMain.unJar()` or `FileLocalizer.expand()`. Neither of the two vulnerable functions performs any other path validation of its own.

## Proof of Concept

`poc/build_and_run.sh` clones `cdapio/cdap` fresh at the pinned commit, installs a JDK and slf4j via apt (no Maven, no pre-built jars), and runs three harnesses in sequence:

1. **`ZipSlipDataprocJobMainPoc`** — byte-exact extraction of the real `DataprocJobMain.unJar()` (lines 221–258, self-verified via `cmp` against the live checkout), driven against a crafted zip with a `../../outside-extraction-dir/pwned.txt` entry. File appears outside the target directory: `BUG CONFIRMED`.
2. **`ZipSlipFileLocalizerPoc`** — byte-exact extraction of the real `FileLocalizer.expand()` (lines 163–180, same verification), identical attack. File appears outside: `BUG CONFIRMED`.
3. **`ZipSlipControl_BundleJarUtil`** — byte-exact extraction of the real `BundleJarUtil.unJar()` (lines 309–369), identical payload. Throws `IllegalArgumentException`, file does not appear: `CONTROL CONFIRMED`.

The harnesses are the only files in this package that are not verbatim source from the cdapio/cdap repo. Each harness contains only the minimum surrounding class/import scaffolding needed to compile the extracted methods in isolation, since the full source files depend on Hadoop/YARN/Twill/logback that these specific methods never touch. The extracted code is otherwise identical, character for character.

Captured output from an actual run is in `captured_output.txt`. `.github/workflows/verify-poc.yml` runs the identical script on GitHub's own infrastructure for independent, third-party reproduction.

**What is not independently verified here (disclosed, not resolved):** the exact "archive" source that provides a zip with fully attacker-controlled entry names in a real CDAP/Cloud Data Fusion program run. Multiple candidate sources flow through these functions (plugin archives, resources jar, runtime config jar, application jar) and each was investigated across the program-startup code paths (DistributedProgramRunner, AbstractRuntimeTwillPreparer, ProgramRunners.createPluginArchive). Plugin archive entry names appear to be derived from CDAP's own artifact storage scheme (artifact-id/version naming, which goes through EntityId validation); the other candidate sources (resources jar, runtime config jar) are populated by CDAP's own internal logic. None was conclusively found to carry a fully user-supplied, unvalidated file path as a zip entry name within this investigation's scope. The core defect — missing containment check in both extraction functions, contrasted with the identical check present in the sibling — is proven directly by live execution and direct code comparison regardless of this open reachability question. A reviewer with full visibility into every caller of `DataprocJobMain.expandArchives()` and `FileLocalizer.expand()`, including any proprietary MasterEnvironment SPI implementations not in the open-source repo, would be best placed to confirm the precise exploitation path.

## Impact

**DataprocJobMain.unJar()** runs as part of the CDAP job bootstrap process executing directly on a real Dataproc cluster VM — an actual GCP compute instance, not a managed container. The process is launched by CDAP's Dataproc runtime job manager when any CDAP program configured to use Dataproc as its execution environment starts. Arbitrary file write outside the extraction directory on that VM means writing to any path the job process's OS user can reach — depending on that user's permissions, this includes locations that allow escalation to full code execution on the cloud VM (e.g., `~/.ssh/authorized_keys`, crontab files, scripts that the init process or future job steps will execute). This is infrastructure-level impact: the target is not a CDAP container, it is an actual GCP-managed Dataproc cluster node.

**FileLocalizer.expand()** runs inside the init container of every CDAP program pod in CDAP's native Kubernetes runtime (the `cdap-kubernetes` module's `FileLocalizer` class, used by `KubeTwillPreparer`'s file-localization init container for all program types — Service, Worker, Workflow, MapReduce, Spark driver — when CDAP's master environment is Kubernetes). Init containers in Kubernetes share volumes with the main container. Writing a file outside the intended extraction directory to a location that the main container's process will later read (e.g., a startup script, a JAR on the program's classpath, or a configuration file) allows code execution in the main container. This affects the Cloud Data Fusion managed service's own GKE cluster.

**Suggested fix:** apply the same two-line guard already present in `BundleJarUtil.unJar()` to both vulnerable functions:
```java
Path output = targetDir.resolve(entry.getName()).normalize();
if (!output.startsWith(targetDir.normalize())) {
  throw new IOException("Zip-slip detected: " + entry.getName());
}
```
Alternatively, centralize all three into a single shared extraction utility so the fix applies in one place.

## Honest caveats

- Live-verified: both `BUG CONFIRMED` outcomes (real file written outside extraction directory by the real, unmodified source code), and the `CONTROL CONFIRMED` outcome (identical payload correctly rejected by the sibling).
- Not verified: the specific attacker-reachable input that would provide a zip with an unsanitized entry name in a real Cloud Data Fusion program run (see "What is not independently verified" above). The impact section describes the worst-case if that reachability holds.
