<?php

declare(strict_types=1);

namespace FoxyDB\Support;

use FoxyDB\Exception\FoxyException;

final class FileSystem
{
    public static function ensureDirectory(string $path): void
    {
        if (is_dir($path)) {
            return;
        }
        if (!@mkdir($path, 0770, true) && !is_dir($path)) {
            throw new FoxyException("Unable to create directory: {$path}", 'STORAGE_IO');
        }
    }

    public static function writeAll($stream, string $data): void
    {
        $length = strlen($data);
        $written = 0;
        while ($written < $length) {
            $count = fwrite($stream, $written === 0 ? $data : substr($data, $written));
            if ($count === false || $count === 0) {
                throw new FoxyException('Unable to write storage data.', 'STORAGE_IO');
            }
            $written += $count;
        }
    }

    public static function readExact($stream, int $length, bool $allowEof = false): ?string
    {
        if ($length < 0) {
            throw new FoxyException('Invalid read length.', 'STORAGE_CORRUPT');
        }
        $data = '';
        $read = 0;
        while ($read < $length) {
            $part = fread($stream, $length - $read);
            if ($part === false) {
                throw new FoxyException('Unable to read storage data.', 'STORAGE_IO');
            }
            if ($part === '') {
                if ($allowEof && $data === '' && feof($stream)) {
                    return null;
                }
                throw new FoxyException('Unexpected end of storage data.', 'STORAGE_CORRUPT');
            }
            $data .= $part;
            $read += strlen($part);
        }
        return $data;
    }

    public static function flush($stream, bool $sync): void
    {
        if (!fflush($stream)) {
            throw new FoxyException('Unable to flush storage data.', 'STORAGE_IO');
        }
        if ($sync && function_exists('fsync') && !fsync($stream)) {
            throw new FoxyException('Unable to synchronize storage data.', 'STORAGE_IO');
        }
    }

    public static function atomicWrite(
        string $path,
        string $data,
        bool $sync = true,
        ?int $permissions = null,
    ): void
    {
        self::ensureDirectory(dirname($path));
        $temporary = $path . '.tmp.' . bin2hex(random_bytes(8));
        $stream = @fopen($temporary, 'xb');
        if ($stream === false) {
            throw new FoxyException("Unable to create temporary file: {$temporary}", 'STORAGE_IO');
        }

        try {
            if ($permissions !== null && DIRECTORY_SEPARATOR === '/' && !chmod($temporary, $permissions)) {
                throw new FoxyException("Unable to secure temporary file: {$temporary}", 'STORAGE_IO');
            }
            self::writeAll($stream, $data);
            self::flush($stream, $sync);
            fclose($stream);
        } catch (\Throwable $exception) {
            if (is_resource($stream)) {
                fclose($stream);
            }
            @unlink($temporary);
            throw $exception;
        }

        if (!@rename($temporary, $path)) {
            @unlink($temporary);
            throw new FoxyException("Unable to replace file: {$path}", 'STORAGE_IO');
        }
        if ($permissions !== null && DIRECTORY_SEPARATOR === '/' && !chmod($path, $permissions)) {
            throw new FoxyException("Unable to secure file permissions: {$path}", 'STORAGE_IO');
        }
        if ($sync && DIRECTORY_SEPARATOR === '/' && function_exists('fsync')) {
            $directory = @fopen(dirname($path), 'rb');
            if (is_resource($directory)) {
                @fsync($directory);
                fclose($directory);
            }
        }
    }

    public static function readMetadata(string $path): array
    {
        $stream = @fopen($path, 'rb');
        if ($stream === false) {
            throw new FoxyException("Unable to read file: {$path}", 'STORAGE_IO');
        }
        try {
            $statistics = fstat($stream);
            if ($statistics === false || $statistics['size'] < BinaryMetadata::HEADER_BYTES
                || $statistics['size'] > BinaryMetadata::HEADER_BYTES + BinaryMetadata::MAXIMUM_BYTES) {
                throw new FoxyException('Binary metadata file has an invalid size.', 'STORAGE_CORRUPT');
            }
            $header = self::readExact($stream, BinaryMetadata::HEADER_BYTES) ?? '';
            $payloadLength = BinaryMetadata::payloadLength($header);
            if ($statistics['size'] !== BinaryMetadata::HEADER_BYTES + $payloadLength) {
                throw new FoxyException('Binary metadata file length does not match its header.', 'STORAGE_CORRUPT');
            }
            $payload = self::readExact($stream, $payloadLength) ?? '';
            return BinaryMetadata::decode($header . $payload);
        } finally {
            fclose($stream);
        }
    }

    public static function writeMetadata(string $path, array $value, bool $sync = true): void
    {
        self::atomicWrite($path, BinaryMetadata::encode($value), $sync);
    }

    public static function copyTree(string $source, string $target): void
    {
        if (is_file($source)) {
            if (!@copy($source, $target)) {
                throw new FoxyException("Unable to copy file: {$source}", 'STORAGE_IO');
            }
            return;
        }

        self::ensureDirectory($target);
        $entries = scandir($source);
        if ($entries === false) {
            throw new FoxyException("Unable to scan directory: {$source}", 'STORAGE_IO');
        }
        foreach ($entries as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                self::copyTree($source . DIRECTORY_SEPARATOR . $entry, $target . DIRECTORY_SEPARATOR . $entry);
            }
        }
    }

    public static function removeTree(string $path): void
    {
        if (!file_exists($path)) {
            return;
        }
        if (is_file($path) || is_link($path)) {
            if (!@unlink($path)) {
                throw new FoxyException("Unable to remove file: {$path}", 'STORAGE_IO');
            }
            return;
        }

        $entries = scandir($path);
        if ($entries === false) {
            throw new FoxyException("Unable to scan directory: {$path}", 'STORAGE_IO');
        }
        foreach ($entries as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                self::removeTree($path . DIRECTORY_SEPARATOR . $entry);
            }
        }
        if (!@rmdir($path)) {
            throw new FoxyException("Unable to remove directory: {$path}", 'STORAGE_IO');
        }
    }
}
