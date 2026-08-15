<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\BinaryMetadata;
use FoxyDB\Support\BinaryCodec;

$metadata = [
    'null' => null,
    'booleans' => [true, false],
    'integers' => [0, -1, PHP_INT_MAX, PHP_INT_MIN],
    'float' => 1234.5678,
    'binary_string' => "a\0b\xff",
    'list' => ['one', 'two', ['nested' => 'value']],
    'empty' => [],
];

$encoded = BinaryMetadata::encode($metadata);
if (substr($encoded, 0, 4) !== 'FXMD') {
    throw new RuntimeException('Binary metadata magic is missing.');
}
if (BinaryMetadata::decode($encoded) !== $metadata) {
    throw new RuntimeException('Binary metadata did not round trip exactly.');
}

foreach ([0, 1, 65_535, 65_536, PHP_INT_MAX] as $integer) {
    if (BinaryCodec::readUint64(BinaryCodec::uint64($integer)) !== $integer) {
        throw new RuntimeException('Portable uint64 codec did not round trip.');
    }
}
$uint32Maximum = PHP_INT_SIZE === 8 ? 65_535 * 65_536 + 65_535 : PHP_INT_MAX;
if (BinaryCodec::readUint32(BinaryCodec::uint32($uint32Maximum)) !== $uint32Maximum) {
    throw new RuntimeException('Portable uint32 codec did not round trip.');
}
if (!hash_equals(BinaryCodec::crc32('portable-crc'), hash('crc32b', 'portable-crc', true))) {
    throw new RuntimeException('CRC32 was not represented as architecture-neutral bytes.');
}
if (PHP_INT_SIZE === 4) {
    try {
        BinaryCodec::readUint32("\xff\xff\xff\xff");
        throw new RuntimeException('Out-of-platform uint32 was accepted.');
    } catch (FoxyException $exception) {
        if ($exception->errorCode !== 'PLATFORM_LIMIT') {
            throw $exception;
        }
    }
}

$corrupt = $encoded;
$corrupt[strlen($corrupt) - 1] = chr(ord($corrupt[strlen($corrupt) - 1]) ^ 0x01);
try {
    BinaryMetadata::decode($corrupt);
    throw new RuntimeException('Corrupt binary metadata was accepted.');
} catch (FoxyException $exception) {
    if ($exception->errorCode !== 'STORAGE_CORRUPT') {
        throw $exception;
    }
}

try {
    BinaryMetadata::decode($encoded . "\0");
    throw new RuntimeException('Trailing binary metadata was accepted.');
} catch (FoxyException $exception) {
    if ($exception->errorCode !== 'STORAGE_CORRUPT') {
        throw $exception;
    }
}

$malformedPayload = chr(7) . pack('N', 1) . pack('N', 5) . 'value' . chr(3) . chr(2) . "1\n";
$malformedInteger = 'FXMD' . pack('nnN', 1, 0, strlen($malformedPayload))
    . hash('crc32b', $malformedPayload, true) . $malformedPayload;
try {
    BinaryMetadata::decode($malformedInteger);
    throw new RuntimeException('Malformed binary metadata integer was accepted.');
} catch (FoxyException $exception) {
    if ($exception->errorCode !== 'STORAGE_CORRUPT') {
        throw $exception;
    }
}

echo "metadata: ok\n";
