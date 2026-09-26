package dev.securegateway.secure_api_gateway.security;

import io.micrometer.core.instrument.MeterRegistry;
import org.apache.tika.Tika;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Set;

@Component
public class FileUploadValidator {
    private static final long MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5MB

    // Allowlist, not blocklist — only these real, detected content types are accepted.
    private static final Set<String> ALLOWED_MIME_TYPES = Set.of(
            "image/png", "image/jpeg", "image/gif",
            "application/pdf",
            "text/plain", "text/csv"
    );

    // Extensions that should never be accepted regardless of detected content —
    // defense in depth on top of the MIME allowlist above.
    private static final Set<String> BLOCKED_EXTENSIONS = Set.of(
            ".exe", ".sh", ".bat", ".jsp", ".jar", ".php", ".dll", ".msi"
    );

    private final MeterRegistry meterRegistry;

    public FileUploadValidator(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    private final Tika tika = new Tika();

    public ValidationResult validate(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            meterRegistry.counter("gateway.security.blocked", "reason", "file_upload").increment();
            return ValidationResult.invalid("File is empty or missing.");
        }

        // Validate file size
        if (file.getSize() > MAX_FILE_SIZE_BYTES) {
            meterRegistry.counter("gateway.security.blocked", "reason", "file_upload").increment();
            return ValidationResult.invalid("File exceeds maximum allowed size of 5MB.");
        }

        // Check for file extensions
        String filename = file.getOriginalFilename();
        if (filename != null) {
            String lower = filename.toLowerCase();
            for (String blocked : BLOCKED_EXTENSIONS) {
                if (lower.endsWith(blocked)) {
                    meterRegistry.counter("gateway.security.blocked", "reason", "file_upload").increment();
                    return ValidationResult.invalid("File extension is not allowed: " + blocked);
                }
            }
        }

        try {
            // Validate mime type
            // This is the real check — detect content from actual bytes,
            // ignoring whatever the client claimed via filename or Content-Type header.
            String detectedType = tika.detect(file.getInputStream());

            if (!ALLOWED_MIME_TYPES.contains(detectedType)) {
                meterRegistry.counter("gateway.security.blocked", "reason", "file_upload").increment();
                return ValidationResult.invalid(
                        "Detected file content type is not allowed: " + detectedType);
            }

            // Cross-check: does the claimed Content-Type header match reality?
            // A mismatch (e.g. an .exe renamed to photo.png) is itself suspicious.
            String claimedType = file.getContentType();
            if (claimedType != null && !claimedType.equals(detectedType)) {
                meterRegistry.counter("gateway.security.blocked", "reason", "file_upload").increment();
                return ValidationResult.invalid(
                        "File content does not match its declared type (claimed: "
                                + claimedType + ", detected: " + detectedType + ").");
            }

        } catch (IOException e) {
            meterRegistry.counter("gateway.security.blocked", "reason", "file_upload").increment();
            return ValidationResult.invalid("Could not read file content for validation.");
        }

        return ValidationResult.valid();
    }

    public record ValidationResult(boolean isValid, String reason) {
        static ValidationResult valid() {
            return new ValidationResult(true, null);
        }

        static ValidationResult invalid(String reason) {
            return new ValidationResult(false, reason);
        }
    }
}
