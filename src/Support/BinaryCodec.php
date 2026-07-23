<?php

declare(strict_types=1);

namespace FoxyDB\Support;

use FoxyDB\Exception\FoxyException;

final class BinaryCodec
{
    private const UINT32_BASE = 4_294_967_296;

    public static function uint64(int $value): string
    {
        if ($value < 0) {
            throw new FoxyException('A negative value cannot be encoded as uint64.', 'STORAGE_CORRUPT');
        }
        $high = intdiv($value, self::UINT32_BASE);
        $low = $value % self::UINT32_BASE;
        return pack('NN', $high, $low);
    }

    public static function readUint64(string $data, int $offset = 0): int
    {
        $parts = unpack('Nhigh/Nlow', substr($data, $offset, 8));
        if ($parts === false) {
            throw new FoxyException('Unable to decode uint64.', 'STORAGE_CORRUPT');
        }
        $value = $parts['high'] * self::UINT32_BASE + $parts['low'];
        if ($value > PHP_INT_MAX) {
            throw new FoxyException('Stored integer exceeds this platform limit.', 'STORAGE_CORRUPT');
        }
        return (int) $value;
    }

    public static function uint32(int $value): string
    {
        return pack('N', $value & 0xffffffff);
    }

    public static function readUint32(string $data, int $offset = 0): int
    {
        $part = unpack('Nvalue', substr($data, $offset, 4));
        if ($part === false) {
            throw new FoxyException('Unable to decode uint32.', 'STORAGE_CORRUPT');
        }
        return (int) $part['value'];
    }

    public static function crc32(string $data): int
    {
        return (int) sprintf('%u', crc32($data));
    }
}
