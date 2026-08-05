package software.coley.recaf.services.workspace.io;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import me.darknet.dex.tree.codec.definition.CodeCodec;
import org.objectweb.asm.ClassReader;
import org.slf4j.Logger;
import software.coley.cafedude.classfile.VersionConstants;
import software.coley.recaf.analytics.logging.Logging;
import software.coley.recaf.info.FileInfo;
import software.coley.recaf.info.Info;
import software.coley.recaf.info.JvmClassInfo;
import software.coley.recaf.info.builder.ArscFileInfoBuilder;
import software.coley.recaf.info.builder.AudioFileInfoBuilder;
import software.coley.recaf.info.builder.BinaryXmlFileInfoBuilder;
import software.coley.recaf.info.builder.DexFileInfoBuilder;
import software.coley.recaf.info.builder.FileInfoBuilder;
import software.coley.recaf.info.builder.ImageFileInfoBuilder;
import software.coley.recaf.info.builder.JvmClassInfoBuilder;
import software.coley.recaf.info.builder.ModulesFileInfoBuilder;
import software.coley.recaf.info.builder.NativeLibraryFileInfoBuilder;
import software.coley.recaf.info.builder.VideoFileInfoBuilder;
import software.coley.recaf.info.builder.ZipFileInfoBuilder;
import software.coley.recaf.info.properties.builtin.IllegalClassSuspectProperty;
import software.coley.recaf.info.properties.builtin.ZipMarkerProperty;
import software.coley.recaf.services.text.TextFormatConfig;
import software.coley.recaf.util.ByteHeaderUtil;
import software.coley.recaf.util.IOUtil;
import software.coley.recaf.util.android.AndroidXmlUtil;
import software.coley.recaf.util.io.ByteSource;

import java.io.IOException;

/**
 * Basic implementation of the info importer.
 *
 * @author Matt Coley
 */
@ApplicationScoped
public class BasicInfoImporter implements InfoImporter {
	private static final Logger logger = Logging.get(BasicInfoImporter.class);
	private final ClassPatcher classPatcher;
	private final InfoImporterConfig config;
	private final TextFormatConfig formatConfig;

	@Inject
	public BasicInfoImporter(@Nonnull InfoImporterConfig config, @Nonnull TextFormatConfig formatConfig, @Nonnull ClassPatcher classPatcher) {
		this.config = config;
		this.formatConfig = formatConfig;
		this.classPatcher = classPatcher;
	}

	@Nonnull
	@Override
	public Info readInfo(@Nonnull String name, @Nonnull ByteSource source) throws IOException {
		byte[] data = source.readAll();

		// Check for Java classes
		if (matchesClass(data)) {
			try {
				return readClass(name, data);
			} catch (Throwable t) {
				// Invalid class. There are a few possibilities here:
				// - The user has disabled patching in their settings and opened an obfuscated file that kills ASM.
				// - There is a pattern in the file very similar to a class file, but it is not actually a class file.
				// - There is an edge case we need to add to CafeDude to allow complete patching.
				return new FileInfoBuilder<>()
						.withRawContent(data)
						.withName(name)
						.withProperty(IllegalClassSuspectProperty.INSTANCE)
						.build();
			}
		}

		// Comparing against known file types.
		boolean hasZipMarker = ByteHeaderUtil.matchAtAnyOffset(data, ByteHeaderUtil.ZIP);
		FileInfo info = readAsSpecializedFile(name, data);
		if (info != null) {
			if (hasZipMarker)
				ZipMarkerProperty.set(info);
			return info;
		}

		// Check for ZIP containers (For ZIP/JAR/JMod/WAR)
		//  - While this is more common, some of the known file types may match 'ZIP' with
		//    our 'any-offset' condition we have here.
		//  - We need 'any-offset' to catch all ZIP cases, but it can match some of the file types
		//    above in some conditions, which means we have to check for it last.
		if (hasZipMarker) {
			ZipFileInfoBuilder builder = new ZipFileInfoBuilder()
					.withProperty(new ZipMarkerProperty())
					.withRawContent(data)
					.withName(name);

			// Record name, handle extension to determine info-type
			String extension = IOUtil.getExtension(name);
			if (extension == null) return builder.build();
			return switch (extension.toUpperCase()) {
				case "JAR" -> builder.asJar().build();
				case "APK" -> builder.asApk().build();
				case "WAR" -> builder.asWar().build();
				case "JMOD" -> builder.asJMod().build();
				default -> builder.build();
			};
		}

		// No special case known for file, treat as generic file
		// Will be automatically mapped to a text file if the contents are all mappable characters.
		return new FileInfoBuilder<>()
				.withRawContent(data)
				.withName(name)
				.build();
	}

	/**
	 * @param name
	 * 		Name of file.
	 * @param data
	 * 		File content.
	 *
	 * @return The {@link FileInfo} subtype of matched special cases <i>(Media, executables, etc.)</i>
	 * or {@code null} if no special case is matched.
	 */
	@Nullable
	private static FileInfo readAsSpecializedFile(@Nonnull String name, byte[] data) {
		if (ByteHeaderUtil.match(data, ByteHeaderUtil.DEX)) {
			CodeCodec.readDebug = false; // TODO: Remove this flag when debug parsing is fixed upstream.
			return new DexFileInfoBuilder()
					.withRawContent(data)
					.withName(name)
					.build();
		} else if (ByteHeaderUtil.match(data, ByteHeaderUtil.MODULES)) {
			return new ModulesFileInfoBuilder()
					.withRawContent(data)
					.withName(name)
					.build();
		} else if (name.toUpperCase().endsWith(".ARSC") &&
				ByteHeaderUtil.match(data, ByteHeaderUtil.ARSC)) {
			return new ArscFileInfoBuilder()
					.withRawContent(data)
					.withName(name)
					.build();
		} else if (name.toUpperCase().endsWith(".XML") &&
				(ByteHeaderUtil.match(data, ByteHeaderUtil.BINARY_XML) || AndroidXmlUtil.hasXmlIndicators(data))) {
			return new BinaryXmlFileInfoBuilder()
					.withRawContent(data)
					.withName(name)
					.build();
		} else if (ByteHeaderUtil.matchAny(data, ByteHeaderUtil.IMAGE_HEADERS)) {
			return new ImageFileInfoBuilder()
					.withRawContent(data)
					.withName(name)
					.build();
		} else if (ByteHeaderUtil.matchAny(data, ByteHeaderUtil.AUDIO_HEADERS)) {
			return new AudioFileInfoBuilder()
					.withRawContent(data)
					.withName(name)
					.build();
		} else if (ByteHeaderUtil.matchAny(data, ByteHeaderUtil.VIDEO_HEADERS)) {
			return new VideoFileInfoBuilder()
					.withRawContent(data)
					.withName(name)
					.build();
		} else if (ByteHeaderUtil.matchAny(data, ByteHeaderUtil.PROGRAM_HEADERS)) {
			return new NativeLibraryFileInfoBuilder()
					.withRawContent(data)
					.withName(name)
					.build();
		}
		return null;
	}

	@Nonnull
	private Info readClass(@Nonnull String name, @Nonnull byte[] data) throws Throwable {
		var patchingMode = config.getClassPatchMode();

		// If we're skipping validation just parse the class file as-is and don't run validation checks.
		// Because the validation steps are skipped problems that would otherwise be caught and patched with
		// higher tier patch modes will occur when opening the class later. Users must accept this responsibility
		// if they want the boost in workspace load speeds.
		if (patchingMode == InfoImporterConfig.ClassPatchMode.SKIP_FILTER)
			// We still do not use 'SKIP_CODE' since we want the info models to have things like variable metadata.
			return new JvmClassInfoBuilder(data, 0).build();

		// If we're always validating, patch the class and try and parse the patched output.
		// Any ASM parse failures imply patching has failed, and the class will be treated as a file instead (see catch block in calling methods)
		if (patchingMode == InfoImporterConfig.ClassPatchMode.ALWAYS_FILTER) {
			byte[] patched = classPatcher.patch(name, data);
			return new JvmClassInfoBuilder(patched, 0)
					.skipValidationChecks(false)
					.build();
		}

		// ASM recursively expands CONSTANT_Dynamic bootstrap arguments when it copies a class into a ClassWriter.
		// Filter hostile bootstrap graphs before any validation step can trigger that expansion.
		byte[] prefiltered = classPatcher.prefilter(name, data);
		if (prefiltered != null)
			data = prefiltered;

		// We're doing a check-then-filter. If ASM reads the class as-is without issue, keep the result.
		// Otherwise, patch when we encounter parse problems and try again.
		int readerFlags = patchingMode == InfoImporterConfig.ClassPatchMode.CHECK_ADVANCED_THEN_FILTER ? ClassReader.SKIP_CODE : 0;
		try {
			return new JvmClassInfoBuilder()
					.skipValidationChecks(false)
					.adaptFrom(data, readerFlags)
					.build();
		} catch (Throwable t) {
			// Patch if not compatible with ASM
			byte[] patched = classPatcher.patch(name, data);
			try {
				JvmClassInfo patchedClassInfo = new JvmClassInfoBuilder(patched, readerFlags)
						.skipValidationChecks(false)
						.build();
				logger.debug("CafeDude patched class: {}", name);
				return patchedClassInfo;
			} catch (Throwable t1) {
				logger.error("CafeDude patching output is still non-compliant with ASM for file: {}", formatConfig.filter(name));
				throw t1;
			}
		}
	}


	/**
	 * Check if the byte array is prefixed by the class file magic header.
	 *
	 * @param content
	 * 		File content.
	 *
	 * @return If the content seems to be a class at a first glance.
	 */
	private static boolean matchesClass(byte[] content) {
		// Null and size check
		// The smallest valid class possible that is verifiable is 37 bytes AFAIK, but we'll be generous here.
		if (content == null || content.length <= 16)
			return false;

		// We want to make sure the 'magic' is correct.
		if (!ByteHeaderUtil.match(content, ByteHeaderUtil.CLASS))
			return false;

		// 'dylib' files can also have CAFEBABE as a magic header... Gee, thanks Apple :/
		// Because of this we'll employ some more sanity checks.
		// Version number must be non-zero
		int version = ((content[6] & 0xFF) << 8) + (content[7] & 0xFF);
		if (version < VersionConstants.JAVA1)
			return false;

		// Must include some constant pool entries.
		// The smallest number includes:
		//  - utf8  - name of current class
		//  - class - wrapper of prior
		//  - utf8  - name of object class
		//  - class - wrapper of prior
		int cpSize = ((content[8] & 0xFF) << 8) + (content[9] & 0xFF);
		if (cpSize < 4)
			return false;

		// JVM constant-pool tags are strictly in {@code 1..20}. Obfuscators sometimes corrupt the constant pool
		// (e.g. the CP tag of an early entry points to a value outside this range) in order to break static
		// analysis tools. Such "classes" cannot survive CafeDude reading, so we must NOT classify them as classes
		// in the first place - otherwise an entire entry (or in the worst case an entire stub-prefixed JAR whose
		// leading bytes look like a CAFEBABE class header) is treated as a single broken class instead of a ZIP
		// container, and nothing inside can ever be loaded.
		//
		// We only need to guard the *first* few CP entries: any class that is broken this quickly is not a real
		// class regardless. This keeps the pre-check cheap for genuine (potentially large) constant pools.
		if (!hasLegalConstantPoolHeader(content, cpSize))
			return false;

		return true;
	}

	/**
	 * Checks that the first few constant-pool entries use only legal JVM tags ({@code 1..20}).
	 *
	 * @param content
	 * 		Class file bytes, starting with a {@code CAFEBABE} header.
	 * @param cpCount
	 * 		Declared constant-pool count ({@code cp_index}).
	 *
	 * @return {@code false} only when an out-of-range tag is encountered in the first few CP entries.
	 * Content that is simply too short to inspect further is treated leniently so that genuine
	 * (potentially truncated) class files keep flowing to {@link BasicClassPatcher} for recovery.
	 */
	private static boolean hasLegalConstantPoolHeader(byte[] content, int cpCount) {
		// Constant pool starts right after magic(4) + minor(2) + major(2) + count(2).
		int pos = 10;
		int maxEntries = Math.min(cpCount, 16);
		for (int i = 1; i < maxEntries; i++) {
			// Too short to read further CP entries -> be lenient, let downstream patching decide.
			if (pos >= content.length)
				return true;

			// Tag must be a legal JVM constant-pool tag (1..20). An out-of-range tag here means the content is
			// definitively not a class (e.g. an obfuscator-corrupted pool, or a stub-prefixed JAR whose leading
			// bytes merely look like a CAFEBABE class header).
			int tag = content[pos] & 0xFF;
			if (!isLegalConstantPoolTag(tag))
				return false;

			pos++; // consume tag byte
			// Advance by the size of the entry's payload (already positioned past the tag).
			switch (tag) {
				case 1: { // UTF8: u2 length + bytes
					if (pos + 2 > content.length)
						return true;
					int len = ((content[pos] & 0xFF) << 8) | (content[pos + 1] & 0xFF);
					pos += 2;
					if (pos + len > content.length)
						return true;
					pos += len;
					break;
				}
				case 3, 4: // Integer, Float: u4
					pos += 4;
					break;
				case 5, 6: { // Long, Double: u8 (occupies two CP slots)
					pos += 8;
					i++;
					break;
				}
				case 7, 8, 16, 19, 20: // Class, String, MethodType, Module, Package: u2 index
					pos += 2;
					break;
				case 9, 10, 11, 12, 17, 18: // Field/Method/InterfaceMethodref, NameAndType, Dynamic, InvokeDynamic: u4
					pos += 4;
					break;
				case 15: // MethodHandle: u1 ref-kind + u2 index
					pos += 3;
					break;
				default:
					return false;
			}
			if (pos > content.length)
				return true;
		}
		return true;
	}

	/**
	 * @param tag
	 * 		Constant-pool tag byte.
	 *
	 * @return Whether the tag is a legal JVM constant-pool tag ({@code 1..20}).
	 */
	private static boolean isLegalConstantPoolTag(int tag) {
		// Valid tags: UTF8=1, Integer=3, Float=4, Long=5, Double=6, Class=7, String=8,
		// Fieldref=9, Methodref=10, InterfaceMethodref=11, NameAndType=12,
		// MethodHandle=15, MethodType=16, Dynamic=17, InvokeDynamic=18, Module=19, Package=20.
		// Tags 2, 13, 14 are reserved/unused and never appear in valid class files.
		return (tag >= 1 && tag <= 12 && tag != 2) ||
				(tag >= 15 && tag <= 20);
	}

	@Nonnull
	@Override
	public String getServiceId() {
		return SERVICE_ID;
	}

	@Nonnull
	@Override
	public InfoImporterConfig getServiceConfig() {
		return config;
	}
}
