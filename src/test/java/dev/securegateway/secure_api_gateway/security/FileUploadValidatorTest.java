package dev.securegateway.secure_api_gateway.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

import static org.assertj.core.api.Assertions.assertThat;

class FileUploadValidatorTest {

    private SimpleMeterRegistry meterRegistry;
    private FileUploadValidator validator;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        validator = new FileUploadValidator(meterRegistry);
    }

    @Test
    void shouldAcceptValidPngFile() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "image.png",
                "image/png",
                pngSignature()
        );

        FileUploadValidator.ValidationResult result =
                validator.validate(file);

        assertThat(result.isValid()).isTrue();
        assertThat(result.reason()).isNull();
        assertThat(blockedUploadCount()).isZero();
    }

    @Test
    void shouldRejectEmptyFile() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "empty.png",
                "image/png",
                new byte[0]
        );

        FileUploadValidator.ValidationResult result =
                validator.validate(file);

        assertThat(result.isValid()).isFalse();
        assertThat(result.reason()).contains("empty or missing");
        assertBlockedUploadCountIsOne();
    }

    @Test
    void shouldRejectFileExceedingMaximumSize() {
        byte[] oversizedContent = new byte[5 * 1024 * 1024 + 1];

        MockMultipartFile file = new MockMultipartFile(
                "file",
                "large.png",
                "image/png",
                oversizedContent
        );

        FileUploadValidator.ValidationResult result =
                validator.validate(file);

        assertThat(result.isValid()).isFalse();
        assertThat(result.reason()).contains("5MB");
        assertBlockedUploadCountIsOne();
    }

    @Test
    void shouldRejectBlockedFileExtension() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "payload.exe",
                "image/png",
                pngSignature()
        );

        FileUploadValidator.ValidationResult result =
                validator.validate(file);

        assertThat(result.isValid()).isFalse();
        assertThat(result.reason()).contains(".exe");
        assertBlockedUploadCountIsOne();
    }

    @Test
    void shouldRejectContentThatDoesNotMatchDeclaredType() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "image.png",
                "image/jpeg",
                pngSignature()
        );

        FileUploadValidator.ValidationResult result =
                validator.validate(file);

        assertThat(result.isValid()).isFalse();
        assertThat(result.reason())
                .contains("does not match its declared type");
        assertBlockedUploadCountIsOne();
    }

    @Test
    void shouldRejectUnsupportedFileContent() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "payload.bin",
                "application/octet-stream",
                new byte[]{
                        0x00, 0x01, 0x02, 0x03,
                        0x10, 0x20, 0x30, 0x40
                }
        );

        FileUploadValidator.ValidationResult result =
                validator.validate(file);

        assertThat(result.isValid()).isFalse();
        assertThat(result.reason())
                .contains("content type is not allowed");
        assertBlockedUploadCountIsOne();
    }

    private byte[] pngSignature() {
        return new byte[]{
                (byte) 0x89, 0x50, 0x4E, 0x47,
                0x0D, 0x0A, 0x1A, 0x0A
        };
    }

    private double blockedUploadCount() {
        var counter = meterRegistry
                .find("gateway.security.blocked")
                .tag("reason", "file_upload")
                .counter();

        return counter == null ? 0.0 : counter.count();
    }

    private void assertBlockedUploadCountIsOne() {
        assertThat(blockedUploadCount()).isEqualTo(1.0);
    }
}