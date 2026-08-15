<?php

declare(strict_types=1);

namespace FoxyDB\Support;

use FoxyDB\Exception\FoxyException;

final class BinaryMetadata
{
    private const MAGIC = 'FXMD';
    private const VERSION = 1;
    public const HEADER_BYTES = 16;
    public const MAXIMUM_BYTES = 4_194_304;
    private const MAXIMUM_ITEMS = 100_000;
    private const MAXIMUM_DEPTH = 64;

    private const NULL = 0;
    private const FALSE = 1;
    private const TRUE = 2;
    private const INTEGER = 3;
    private const FLOAT = 4;
    private const STRING = 5;
    private const LIST = 6;
    private const MAP = 7;

    public static function encode(
        array $metadata,
        int $maximumBytes = self::MAXIMUM_BYTES,
        int $maximumItems = self::MAXIMUM_ITEMS,
    ): string
    {
        self::validateLimits($maximumBytes, $maximumItems);
        $remainingItems = $maximumItems;
        $remainingBytes = $maximumBytes;
        $payload = self::encodeValue(
            $metadata, 0, $remainingItems, $remainingBytes, $maximumBytes, $maximumItems,
        );
        $length = strlen($payload);
        if ($length > $maximumBytes) {
            throw new FoxyException('Binary metadata exceeds its configured limit.', 'RESOURCE_LIMIT');
        }
        return self::MAGIC
            . pack('nnN', self::VERSION, 0, $length)
            . hash('crc32b', $payload, true)
            . $payload;
    }

    public static function decode(
        string $binary,
        int $maximumBytes = self::MAXIMUM_BYTES,
        int $maximumItems = self::MAXIMUM_ITEMS,
    ): array
    {
        self::validateLimits($maximumBytes, $maximumItems);
        if (strlen($binary) < self::HEADER_BYTES || substr($binary, 0, 4) !== self::MAGIC) {
            throw new FoxyException('Invalid binary metadata header.', 'STORAGE_CORRUPT');
        }
        $length = self::payloadLength(substr($binary, 0, self::HEADER_BYTES), $maximumBytes);
        if (strlen($binary) !== self::HEADER_BYTES + $length) {
            throw new FoxyException('Invalid binary metadata length.', 'STORAGE_CORRUPT');
        }
        $payload = substr($binary, self::HEADER_BYTES);
        if (!hash_equals(substr($binary, 12, 4), hash('crc32b', $payload, true))) {
            throw new FoxyException('Binary metadata checksum mismatch.', 'STORAGE_CORRUPT');
        }

        $offset = 0;
        $remainingItems = $maximumItems;
        $value = self::decodeValue($payload, $offset, 0, $remainingItems, $maximumBytes, $maximumItems);
        if (!is_array($value) || $offset !== $length) {
            throw new FoxyException('Invalid binary metadata root or trailing data.', 'STORAGE_CORRUPT');
        }
        return $value;
    }

    public static function payloadLength(string $header, int $maximumBytes = self::MAXIMUM_BYTES): int
    {
        self::validateLimits($maximumBytes, 1);
        if (strlen($header) !== self::HEADER_BYTES || substr($header, 0, 4) !== self::MAGIC) {
            throw new FoxyException('Invalid binary metadata header.', 'STORAGE_CORRUPT');
        }
        $decoded = unpack('nversion/nflags/Nlength', substr($header, 4, 8));
        if ($decoded === false || $decoded['version'] !== self::VERSION || $decoded['flags'] !== 0) {
            throw new FoxyException('Unsupported binary metadata version or flags.', 'STORAGE_CORRUPT');
        }
        $length = (int) $decoded['length'];
        if ($length > $maximumBytes) {
            throw new FoxyException('Binary metadata exceeds its size limit.', 'STORAGE_CORRUPT');
        }
        return $length;
    }

    private static function encodeValue(
        mixed $value,
        int $depth,
        int &$remainingItems,
        int &$remainingBytes,
        int $maximumBytes,
        int $maximumItems,
    ): string
    {
        self::checkDepth($depth);
        if ($value === null) {
            self::consumeBytes($remainingBytes, 1);
            return chr(self::NULL);
        }
        if ($value === false) {
            self::consumeBytes($remainingBytes, 1);
            return chr(self::FALSE);
        }
        if ($value === true) {
            self::consumeBytes($remainingBytes, 1);
            return chr(self::TRUE);
        }
        if (is_int($value)) {
            $integer = (string) $value;
            self::consumeBytes($remainingBytes, 2 + strlen($integer));
            return chr(self::INTEGER) . chr(strlen($integer)) . $integer;
        }
        if (is_float($value)) {
            if (!is_finite($value)) {
                throw new FoxyException('Binary metadata cannot contain a non-finite float.', 'STORAGE_IO');
            }
            self::consumeBytes($remainingBytes, 9);
            return chr(self::FLOAT) . pack('E', $value);
        }
        if (is_string($value)) {
            $length = strlen($value);
            if ($length > $maximumBytes) {
                throw new FoxyException('Binary metadata string is too large.', 'RESOURCE_LIMIT');
            }
            self::consumeBytes($remainingBytes, 5 + $length);
            return chr(self::STRING) . BinaryCodec::uint32($length) . $value;
        }
        if (!is_array($value)) {
            throw new FoxyException('Binary metadata contains an unsupported value.', 'STORAGE_IO');
        }
        if (count($value) > $maximumItems) {
            throw new FoxyException('Binary metadata collection has too many items.', 'RESOURCE_LIMIT');
        }
        $remainingItems -= count($value);
        if ($remainingItems < 0) {
            throw new FoxyException('Binary metadata has too many aggregate items.', 'RESOURCE_LIMIT');
        }

        if (array_is_list($value)) {
            self::consumeBytes($remainingBytes, 5);
            $encoded = chr(self::LIST) . BinaryCodec::uint32(count($value));
            foreach ($value as $item) {
                $encoded .= self::encodeValue(
                    $item, $depth + 1, $remainingItems, $remainingBytes, $maximumBytes, $maximumItems,
                );
            }
            return $encoded;
        }

        self::consumeBytes($remainingBytes, 5);
        $encoded = chr(self::MAP) . BinaryCodec::uint32(count($value));
        foreach ($value as $key => $item) {
            if (!is_string($key)) {
                throw new FoxyException('Binary metadata map keys must be strings.', 'STORAGE_IO');
            }
            $keyLength = strlen($key);
            if ($keyLength > $maximumBytes) {
                throw new FoxyException('Binary metadata map key is too large.', 'RESOURCE_LIMIT');
            }
            self::consumeBytes($remainingBytes, 4 + $keyLength);
            $encoded .= BinaryCodec::uint32($keyLength) . $key;
            $encoded .= self::encodeValue(
                $item, $depth + 1, $remainingItems, $remainingBytes, $maximumBytes, $maximumItems,
            );
        }
        return $encoded;
    }

    private static function decodeValue(
        string $payload,
        int &$offset,
        int $depth,
        int &$remainingItems,
        int $maximumBytes,
        int $maximumItems,
    ): mixed
    {
        self::checkDepth($depth);
        $type = ord(self::take($payload, $offset, 1));
        return match ($type) {
            self::NULL => null,
            self::FALSE => false,
            self::TRUE => true,
            self::INTEGER => self::decodeInteger($payload, $offset),
            self::FLOAT => self::decodeFloat($payload, $offset),
            self::STRING => self::decodeString($payload, $offset, $maximumBytes),
            self::LIST => self::decodeList(
                $payload, $offset, $depth + 1, $remainingItems, $maximumBytes, $maximumItems,
            ),
            self::MAP => self::decodeMap(
                $payload, $offset, $depth + 1, $remainingItems, $maximumBytes, $maximumItems,
            ),
            default => throw new FoxyException('Unknown binary metadata value type.', 'STORAGE_CORRUPT'),
        };
    }

    private static function decodeInteger(string $payload, int &$offset): int
    {
        $length = ord(self::take($payload, $offset, 1));
        if ($length < 1 || $length > 20) {
            throw new FoxyException('Invalid binary metadata integer length.', 'STORAGE_CORRUPT');
        }
        $encoded = self::take($payload, $offset, $length);
        if (preg_match('/^-?(?:0|[1-9][0-9]*)\z/', $encoded) !== 1) {
            throw new FoxyException('Invalid binary metadata integer.', 'STORAGE_CORRUPT');
        }
        $value = filter_var($encoded, FILTER_VALIDATE_INT);
        if ($value === false) {
            throw new FoxyException('Binary metadata integer exceeds the platform range.', 'STORAGE_CORRUPT');
        }
        return (int) $value;
    }

    private static function decodeFloat(string $payload, int &$offset): float
    {
        $decoded = unpack('Evalue', self::take($payload, $offset, 8));
        $value = $decoded['value'] ?? NAN;
        if (!is_float($value) || !is_finite($value)) {
            throw new FoxyException('Invalid binary metadata float.', 'STORAGE_CORRUPT');
        }
        return $value;
    }

    private static function decodeString(string $payload, int &$offset, int $maximumBytes): string
    {
        $length = self::decodeLength($payload, $offset, $maximumBytes);
        return self::take($payload, $offset, $length);
    }

    private static function decodeList(
        string $payload, int &$offset, int $depth, int &$remainingItems,
        int $maximumBytes, int $maximumItems,
    ): array
    {
        $count = self::decodeCount($payload, $offset, $remainingItems, $maximumItems);
        $list = [];
        for ($index = 0; $index < $count; $index++) {
            $list[] = self::decodeValue(
                $payload, $offset, $depth, $remainingItems, $maximumBytes, $maximumItems,
            );
        }
        return $list;
    }

    private static function decodeMap(
        string $payload, int &$offset, int $depth, int &$remainingItems,
        int $maximumBytes, int $maximumItems,
    ): array
    {
        $count = self::decodeCount($payload, $offset, $remainingItems, $maximumItems);
        $map = [];
        for ($index = 0; $index < $count; $index++) {
            $keyLength = self::decodeLength($payload, $offset, $maximumBytes);
            $key = self::take($payload, $offset, $keyLength);
            $probe = [];
            $probe[$key] = true;
            if (!is_string(array_key_first($probe))) {
                throw new FoxyException('Binary metadata map key is not type-stable in PHP.', 'STORAGE_CORRUPT');
            }
            if (array_key_exists($key, $map)) {
                throw new FoxyException('Binary metadata contains a duplicate map key.', 'STORAGE_CORRUPT');
            }
            $map[$key] = self::decodeValue(
                $payload, $offset, $depth, $remainingItems, $maximumBytes, $maximumItems,
            );
        }
        return $map;
    }

    private static function decodeLength(string $payload, int &$offset, int $maximumBytes): int
    {
        $length = BinaryCodec::readUint32(self::take($payload, $offset, 4));
        if ($length > $maximumBytes) {
            throw new FoxyException('Binary metadata value exceeds its size limit.', 'STORAGE_CORRUPT');
        }
        return $length;
    }

    private static function decodeCount(
        string $payload, int &$offset, int &$remainingItems, int $maximumItems,
    ): int
    {
        $count = BinaryCodec::readUint32(self::take($payload, $offset, 4));
        if ($count > $maximumItems) {
            throw new FoxyException('Binary metadata collection exceeds its item limit.', 'STORAGE_CORRUPT');
        }
        $remainingItems -= $count;
        if ($remainingItems < 0) {
            throw new FoxyException('Binary metadata exceeds its aggregate item limit.', 'STORAGE_CORRUPT');
        }
        return $count;
    }

    private static function take(string $payload, int &$offset, int $length): string
    {
        if ($length < 0 || $offset < 0 || $offset + $length > strlen($payload)) {
            throw new FoxyException('Unexpected end of binary metadata.', 'STORAGE_CORRUPT');
        }
        $value = substr($payload, $offset, $length);
        $offset += $length;
        return $value;
    }

    private static function checkDepth(int $depth): void
    {
        if ($depth > self::MAXIMUM_DEPTH) {
            throw new FoxyException('Binary metadata nesting is too deep.', 'STORAGE_CORRUPT');
        }
    }

    private static function consumeBytes(int &$remainingBytes, int $bytes): void
    {
        $remainingBytes -= $bytes;
        if ($remainingBytes < 0) {
            throw new FoxyException('Binary metadata exceeds its configured limit.', 'RESOURCE_LIMIT');
        }
    }

    private static function validateLimits(int $maximumBytes, int $maximumItems): void
    {
        if ($maximumBytes < 1 || $maximumItems < 1) {
            throw new FoxyException('Binary metadata limits must be positive.', 'INVALID_CONFIG');
        }
    }
}
