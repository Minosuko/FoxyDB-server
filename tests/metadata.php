<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Exception\FoxyException;
use FoxyDB\Support\BinaryMetadata;

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
