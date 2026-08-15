<?php

declare(strict_types=1);

namespace FoxyDB\Protocol;

use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\FileSystem;
use FoxyDB\Value\BinaryValue;

final class FrameCodec
{
    public const HEADER_BYTES = 16;
    public const VERSION = 2;
    public const MAXIMUM_FRAME_BYTES = 16_777_216;

    private const MAGIC = 'FXDB';
    private const KIND_VALUE = 1;
    private const MAXIMUM_DEPTH = 64;
    private const MAXIMUM_AGGREGATE_ITEMS = 100_000;
    private const NULL = 0;
    private const FALSE = 1;
    private const TRUE = 2;
    private const INTEGER = 3;
    private const FLOAT = 4;
    private const TEXT = 5;
    private const BYTES = 6;
    private const LIST = 7;
    private const MAP = 8;

    public static function encode(array $payload, int $maximumBytes): string
    {
        if ($payload === [] || array_is_list($payload)) {
            throw new FoxyException('Protocol frames require a non-empty map.', 'PROTOCOL_ERROR');
        }
        $body = self::encodeRoot($payload, $maximumBytes);
        $length = strlen($body);
        if ($length > $maximumBytes) {
            throw new FoxyException('Protocol frame exceeds the configured limit.', 'FRAME_TOO_LARGE');
        }
        $prefix = self::MAGIC . chr(self::VERSION) . chr(self::KIND_VALUE) . pack('nN', 0, $length);
        return $prefix . hash('crc32c', $prefix . $body, true) . $body;
    }

    public static function extract(string &$buffer, int $maximumBytes): ?array
    {
        if (strlen($buffer) < 4) {
            return null;
        }
        if (substr($buffer, 0, 4) !== self::MAGIC) {
            throw new FoxyException('Invalid binary protocol header.', 'PROTOCOL_ERROR');
        }
        if (strlen($buffer) < self::HEADER_BYTES) {
            return null;
        }
        $header = substr($buffer, 0, self::HEADER_BYTES);
        $length = self::payloadLength($header, $maximumBytes);
        if (strlen($buffer) < self::HEADER_BYTES + $length) {
            return null;
        }
        $body = substr($buffer, self::HEADER_BYTES, $length);
        self::verifyChecksum($header, $body);
        $payload = self::decodeRoot($body, $maximumBytes);
        $buffer = substr($buffer, self::HEADER_BYTES + $length);
        return $payload;
    }

    public static function write($stream, array $payload, int $maximumBytes): void
    {
        FileSystem::writeAll($stream, self::encode($payload, $maximumBytes));
        FileSystem::flush($stream, false);
    }

    public static function read($stream, int $maximumBytes): array
    {
        $header = self::readNetworkExact($stream, self::HEADER_BYTES);
        $length = self::payloadLength($header, $maximumBytes);
        $body = self::readNetworkExact($stream, $length, true);
        self::verifyChecksum($header, $body);
        return self::decodeRoot($body, $maximumBytes);
    }

    public static function encodedValueBytes(mixed $value, int $maximumBytes = 1_073_741_824): int
    {
        $remainingItems = self::MAXIMUM_AGGREGATE_ITEMS;
        return strlen(self::encodeValue($value, 0, $remainingItems, $maximumBytes));
    }

    private static function encodeRoot(array $payload, int $maximumBytes): string
    {
        if ($maximumBytes < 1 || $maximumBytes > self::MAXIMUM_FRAME_BYTES) {
            throw new FoxyException('Invalid protocol frame limit.', 'INVALID_CONFIG');
        }
        $remainingItems = self::MAXIMUM_AGGREGATE_ITEMS;
        return self::encodeValue($payload, 0, $remainingItems, $maximumBytes);
    }

    private static function encodeValue(
        mixed $value,
        int $depth,
        int &$remainingItems,
        int $maximumBytes,
    ): string {
        if ($depth > self::MAXIMUM_DEPTH) {
            throw new FoxyException('Protocol value exceeds the nesting limit.', 'PROTOCOL_ERROR');
        }
        if ($value === null) {
            return chr(self::NULL);
        }
        if ($value === false) {
            return chr(self::FALSE);
        }
        if ($value === true) {
            return chr(self::TRUE);
        }
        if (is_int($value)) {
            return chr(self::INTEGER) . self::signedInteger($value);
        }
        if (is_float($value)) {
            if (!is_finite($value)) {
                throw new FoxyException('Protocol floats must be finite.', 'PROTOCOL_ERROR');
            }
            return chr(self::FLOAT) . pack('E', $value);
        }
        if (is_string($value)) {
            self::assertUtf8($value, 'Protocol text is not valid UTF-8.');
            return self::lengthPrefixed(self::TEXT, $value, $maximumBytes);
        }
        if ($value instanceof BinaryValue) {
            return self::lengthPrefixed(self::BYTES, $value->bytes, $maximumBytes);
        }
        if (!is_array($value)) {
            throw new FoxyException('Protocol value has an unsupported type.', 'PROTOCOL_ERROR');
        }

        $count = count($value);
        if ($count > $remainingItems) {
            throw new FoxyException('Protocol value contains too many items.', 'PROTOCOL_ERROR');
        }
        $remainingItems -= $count;
        if (array_is_list($value)) {
            $encoded = chr(self::LIST) . pack('N', $count);
            foreach ($value as $item) {
                self::appendBounded(
                    $encoded,
                    self::encodeValue($item, $depth + 1, $remainingItems, $maximumBytes),
                    $maximumBytes,
                );
            }
            return $encoded;
        }

        $encoded = chr(self::MAP) . pack('N', $count);
        foreach ($value as $key => $item) {
            if (!is_string($key) || $key === '' || self::isNumericMapKey($key)) {
                throw new FoxyException('Protocol map keys must be non-empty, non-numeric strings.', 'PROTOCOL_ERROR');
            }
            self::assertUtf8($key, 'Protocol map key is not valid UTF-8.');
            $keyBytes = strlen($key);
            self::appendBounded($encoded, pack('N', $keyBytes) . $key, $maximumBytes);
            self::appendBounded(
                $encoded,
                self::encodeValue($item, $depth + 1, $remainingItems, $maximumBytes),
                $maximumBytes,
            );
        }
        return $encoded;
    }

    private static function decodeRoot(string $body, int $maximumBytes): array
    {
        if ($body === '' || ord($body[0]) !== self::MAP) {
            throw new FoxyException('Protocol frame payload must be a map.', 'PROTOCOL_ERROR');
        }
        $offset = 0;
        $remainingItems = self::MAXIMUM_AGGREGATE_ITEMS;
        $value = self::decodeValue($body, $offset, 0, $remainingItems, $maximumBytes);
        if (!is_array($value) || $value === [] || array_is_list($value) || $offset !== strlen($body)) {
            throw new FoxyException('Protocol frame payload is invalid or has trailing data.', 'PROTOCOL_ERROR');
        }
        return $value;
    }

    private static function decodeValue(
        string $body,
        int &$offset,
        int $depth,
        int &$remainingItems,
        int $maximumBytes,
    ): mixed {
        if ($depth > self::MAXIMUM_DEPTH || $offset >= strlen($body)) {
            throw new FoxyException('Protocol value is truncated or too deeply nested.', 'PROTOCOL_ERROR');
        }
        $tag = ord($body[$offset++]);
        if ($tag === self::NULL) {
            return null;
        }
        if ($tag === self::FALSE) {
            return false;
        }
        if ($tag === self::TRUE) {
            return true;
        }
        if ($tag === self::INTEGER) {
            return self::readSignedInteger(self::take($body, $offset, 8));
        }
        if ($tag === self::FLOAT) {
            $decoded = unpack('Evalue', self::take($body, $offset, 8));
            $value = $decoded['value'] ?? NAN;
            if (!is_float($value) || !is_finite($value)) {
                throw new FoxyException('Protocol float is invalid.', 'PROTOCOL_ERROR');
            }
            return $value;
        }
        if ($tag === self::TEXT || $tag === self::BYTES) {
            $length = self::readLength($body, $offset, $maximumBytes);
            $value = self::take($body, $offset, $length);
            if ($tag === self::TEXT) {
                self::assertUtf8($value, 'Protocol text is not valid UTF-8.');
                return $value;
            }
            return new BinaryValue($value);
        }
        if ($tag !== self::LIST && $tag !== self::MAP) {
            throw new FoxyException('Protocol value has an unknown type tag.', 'PROTOCOL_ERROR');
        }

        $count = self::readUnsigned32($body, $offset);
        if ($count > $remainingItems) {
            throw new FoxyException('Protocol value contains too many items.', 'PROTOCOL_ERROR');
        }
        $remainingItems -= $count;
        if ($tag === self::LIST) {
            $list = [];
            for ($index = 0; $index < $count; $index++) {
                $list[] = self::decodeValue($body, $offset, $depth + 1, $remainingItems, $maximumBytes);
            }
            return $list;
        }

        if ($count === 0) {
            throw new FoxyException('Empty protocol maps are not supported.', 'PROTOCOL_ERROR');
        }

        $map = [];
        $seen = [];
        for ($index = 0; $index < $count; $index++) {
            $keyLength = self::readUnsigned32($body, $offset);
            $key = self::take($body, $offset, $keyLength);
            self::assertUtf8($key, 'Protocol map key is not valid UTF-8.');
            if ($key === '' || self::isNumericMapKey($key) || isset($seen["\0" . $key])) {
                throw new FoxyException('Protocol map key is empty, numeric, or duplicated.', 'PROTOCOL_ERROR');
            }
            $seen["\0" . $key] = true;
            $map[$key] = self::decodeValue($body, $offset, $depth + 1, $remainingItems, $maximumBytes);
        }
        return $map;
    }

    private static function payloadLength(string $header, int $maximumBytes): int
    {
        if ($maximumBytes < 1 || $maximumBytes > self::MAXIMUM_FRAME_BYTES) {
            throw new FoxyException('Invalid protocol frame limit.', 'INVALID_CONFIG');
        }
        if (strlen($header) !== self::HEADER_BYTES || substr($header, 0, 4) !== self::MAGIC
            || ord($header[4]) !== self::VERSION || ord($header[5]) !== self::KIND_VALUE) {
            throw new FoxyException('Invalid binary protocol header.', 'PROTOCOL_ERROR');
        }
        $fields = unpack('nflags/nhigh/nlow', substr($header, 6, 6));
        $flags = (int) ($fields['flags'] ?? -1);
        $high = (int) ($fields['high'] ?? -1);
        $low = (int) ($fields['low'] ?? -1);
        if ($high < 0 || $low < 0 || $high > intdiv(PHP_INT_MAX - $low, 65_536)) {
            throw new FoxyException('Protocol frame length exceeds this platform limit.', 'FRAME_TOO_LARGE');
        }
        $length = $high * 65_536 + $low;
        if ($flags !== 0 || $length < 5) {
            throw new FoxyException('Invalid binary protocol flags or length.', 'PROTOCOL_ERROR');
        }
        if ($length > $maximumBytes) {
            throw new FoxyException('Protocol frame exceeds the configured limit.', 'FRAME_TOO_LARGE');
        }
        return $length;
    }

    private static function verifyChecksum(string $header, string $body): void
    {
        $expected = substr($header, 12, 4);
        $actual = hash('crc32c', substr($header, 0, 12) . $body, true);
        if (!hash_equals($expected, $actual)) {
            throw new FoxyException('Binary protocol checksum mismatch.', 'PROTOCOL_ERROR');
        }
    }

    private static function lengthPrefixed(int $tag, string $value, int $maximumBytes): string
    {
        $length = strlen($value);
        if ($length > $maximumBytes) {
            throw new FoxyException('Protocol scalar exceeds the configured limit.', 'FRAME_TOO_LARGE');
        }
        return chr($tag) . pack('N', $length) . $value;
    }

    private static function appendBounded(string &$target, string $value, int $maximumBytes): void
    {
        if (strlen($value) > $maximumBytes - strlen($target)) {
            throw new FoxyException('Protocol frame exceeds the configured limit.', 'FRAME_TOO_LARGE');
        }
        $target .= $value;
    }

    private static function readLength(string $body, int &$offset, int $maximumBytes): int
    {
        $length = self::readUnsigned32($body, $offset);
        if ($length > $maximumBytes) {
            throw new FoxyException('Protocol scalar exceeds the configured limit.', 'FRAME_TOO_LARGE');
        }
        return $length;
    }

    private static function readUnsigned32(string $body, int &$offset): int
    {
        $decoded = unpack('nhigh/nlow', self::take($body, $offset, 4));
        $high = (int) ($decoded['high'] ?? 0);
        $low = (int) ($decoded['low'] ?? 0);
        if ($high > intdiv(PHP_INT_MAX - $low, 65_536)) {
            throw new FoxyException('Protocol integer exceeds this platform limit.', 'PROTOCOL_ERROR');
        }
        return $high * 65_536 + $low;
    }

    private static function take(string $body, int &$offset, int $length): string
    {
        $available = strlen($body) - $offset;
        if ($length < 0 || $length > $available) {
            throw new FoxyException('Protocol value is truncated.', 'PROTOCOL_ERROR');
        }
        $value = substr($body, $offset, $length);
        $offset += $length;
        return $value;
    }

    private static function signedInteger(int $value): string
    {
        $words = [0, 0, 0, 0];
        for ($index = 3; $index >= 0; $index--) {
            $words[$index] = $value & 0xffff;
            $value >>= 16;
        }
        return pack('nnnn', ...$words);
    }

    private static function readSignedInteger(string $bytes): int
    {
        $parts = unpack('n4', $bytes);
        if ($parts === false || count($parts) !== 4) {
            throw new FoxyException('Protocol integer is invalid.', 'PROTOCOL_ERROR');
        }
        $words = array_values($parts);
        if (PHP_INT_SIZE === 4) {
            $negative = ($words[0] & 0x8000) !== 0;
            $extension = $negative ? 0xffff : 0;
            if ($words[0] !== $extension || $words[1] !== $extension
                || ($negative !== (($words[2] & 0x8000) !== 0))) {
                throw new FoxyException('Protocol integer exceeds this platform limit.', 'PROTOCOL_ERROR');
            }
            return ($words[2] - ($negative ? 65_536 : 0)) * 65_536 + $words[3];
        }
        $negative = ($words[0] & 0x8000) !== 0;
        $value = $words[0] - ($negative ? 65_536 : 0);
        for ($index = 1; $index < 4; $index++) {
            $value = $value * 65_536 + $words[$index];
        }
        return $value;
    }

    private static function assertUtf8(string $value, string $message): void
    {
        if (preg_match('//u', $value) !== 1) {
            throw new FoxyException($message, 'PROTOCOL_ERROR');
        }
    }

    private static function isNumericMapKey(string $key): bool
    {
        return preg_match('/^(?:0|-?[1-9][0-9]*)$/', $key) === 1;
    }

    private static function readNetworkExact($stream, int $length, bool $frameStarted = false): string
    {
        $data = '';
        $read = 0;
        while ($read < $length) {
            $part = @fread($stream, $length - $read);
            if ($part === false) {
                throw new FoxyException('Unable to read from the connection.', 'CONNECTION_IO');
            }
            if ($part === '') {
                $metadata = stream_get_meta_data($stream);
                if (($metadata['timed_out'] ?? false) === true) {
                    throw new FoxyException('Connection read timed out.', 'CONNECTION_TIMEOUT');
                }
                if (feof($stream)) {
                    throw new FoxyException(
                        !$frameStarted && $data === '' ? 'Connection was closed.' : 'Connection closed during a frame.',
                        !$frameStarted && $data === '' ? 'CONNECTION_CLOSED' : 'PROTOCOL_ERROR',
                    );
                }
                continue;
            }
            $data .= $part;
            $read += strlen($part);
        }
        return $data;
    }
}
