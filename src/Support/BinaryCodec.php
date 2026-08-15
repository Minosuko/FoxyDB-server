<?php

declare(strict_types=1);

namespace FoxyDB\Support;

use FoxyDB\Exception\FoxyException;

final class BinaryCodec
{
    public static function uint64(int $value): string
    {
        if ($value < 0) {
            throw new FoxyException('A negative value cannot be encoded as uint64.', 'STORAGE_CORRUPT');
        }
        $words = [0, 0, 0, 0];
        for ($index = 3; $index >= 0; $index--) {
            $words[$index] = $value % 65_536;
            $value = intdiv($value, 65_536);
        }
        return pack('nnnn', ...$words);
    }

    public static function readUint64(string $data, int $offset = 0): int
    {
        $parts = unpack('n4', substr($data, $offset, 8));
        if ($parts === false || count($parts) !== 4) {
            throw new FoxyException('Unable to decode uint64.', 'STORAGE_CORRUPT');
        }
        $value = 0;
        foreach ($parts as $word) {
            if ($value > intdiv(PHP_INT_MAX - $word, 65_536)) {
                throw new FoxyException('Stored integer exceeds this platform limit.', 'PLATFORM_LIMIT');
            }
            $value = $value * 65_536 + $word;
        }
        return $value;
    }

    public static function uint32(int $value): string
    {
        $high = intdiv($value, 65_536);
        if ($value < 0 || $high > 65_535) {
            throw new FoxyException('Value cannot be encoded as uint32.', 'STORAGE_CORRUPT');
        }
        return pack('nn', $high, $value % 65_536);
    }

    public static function readUint32(string $data, int $offset = 0): int
    {
        $part = unpack('nhigh/nlow', substr($data, $offset, 4));
        if ($part === false || !isset($part['high'], $part['low'])) {
            throw new FoxyException('Unable to decode uint32.', 'STORAGE_CORRUPT');
        }
        if ($part['high'] > intdiv(PHP_INT_MAX - $part['low'], 65_536)) {
            throw new FoxyException('Stored integer exceeds this platform limit.', 'PLATFORM_LIMIT');
        }
        return $part['high'] * 65_536 + $part['low'];
    }

    public static function crc32(string $data): string
    {
        return hash('crc32b', $data, true);
    }
}
