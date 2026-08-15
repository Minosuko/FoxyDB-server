<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Exception\FoxyException;
use FoxyDB\Protocol\FrameCodec;
use FoxyDB\Value\BinaryValue;

$expectProtocolError = static function (callable $operation, array $codes = ['PROTOCOL_ERROR']): void {
    try {
        $operation();
    } catch (FoxyException $exception) {
        if (in_array($exception->errorCode, $codes, true)) {
            return;
        }
        throw $exception;
    }
    throw new RuntimeException('Expected binary protocol error was not raised.');
};
$frame = static function (string $body): string {
    $prefix = 'FXDB' . chr(FrameCodec::VERSION) . chr(1) . pack('nN', 0, strlen($body));
    return $prefix . hash('crc32c', $prefix . $body, true) . $body;
};

$bytes = "\0\xff\x80raw-binary\0" . random_bytes(1_024);
$payload = [
    'type' => 'codec_test',
    'null' => null,
    'false' => false,
    'true' => true,
    'minimum' => PHP_INT_MIN,
    'maximum' => PHP_INT_MAX,
    'negative' => -123456789,
    'float' => -123.5,
    'text' => 'FoxyDB protocol',
    'bytes' => new BinaryValue($bytes),
    'list' => [1, 'two', false, new BinaryValue("\x01\x02")],
    'map' => ['nested' => ['value' => 42]],
];

$encoded = FrameCodec::encode($payload, 1_048_576);
if (substr($encoded, 0, 4) !== 'FXDB' || ord($encoded[4]) !== FrameCodec::VERSION
    || ord($encoded[5]) !== 1 || !str_contains($encoded, $bytes)) {
    throw new RuntimeException('Binary frame envelope or raw-byte encoding is incorrect.');
}
$goldenFrame = FrameCodec::encode(['type' => 'ping', 'id' => 7], 1_024);
if (bin2hex($goldenFrame) !== '4658444202010000000000252e0be20f080000000200000004747970650500000004'
    . '70696e67000000026964030000000000000007') {
    throw new RuntimeException('Binary protocol golden frame changed.');
}
$wideIntegerBody = chr(8) . pack('N', 1) . pack('N', 1) . 'v' . chr(3)
    . "\x00\x00\x00\x00\x80\x00\x00\x00";
$wideIntegerFrame = $frame($wideIntegerBody);
if (PHP_INT_SIZE === 4) {
    $expectProtocolError(static function () use ($wideIntegerFrame): void {
        $buffer = $wideIntegerFrame;
        FrameCodec::extract($buffer, 1_024);
    });
} else {
    $wideBuffer = $wideIntegerFrame;
    if (FrameCodec::extract($wideBuffer, 1_024)['v'] !== 2_147_483_648) {
        throw new RuntimeException('Signed 64-bit protocol integer decoded incorrectly.');
    }
}
$legacyJsonBytes = strlen(json_encode([
    'bytes' => ['$binary' => base64_encode($bytes)],
], JSON_THROW_ON_ERROR)) + 4;
$binaryOnly = FrameCodec::encode(['bytes' => new BinaryValue($bytes)], 1_048_576);
if (strlen($binaryOnly) >= $legacyJsonBytes) {
    throw new RuntimeException('Binary protocol did not remove Base64 framing overhead.');
}
$longKey = str_repeat('k', 2_048);
$longKeyFrame = FrameCodec::encode([$longKey => 'value'], 1_048_576);
$longKeyBuffer = $longKeyFrame;
if (FrameCodec::extract($longKeyBuffer, 1_048_576) !== [$longKey => 'value']) {
    throw new RuntimeException('Protocol map key was truncated by the former key ceiling.');
}
$largeContainer = array_fill(0, 70_000, null);
$largeContainerFrame = FrameCodec::encode(['items' => $largeContainer], 1_048_576);
$largeContainerBuffer = $largeContainerFrame;
if (count(FrameCodec::extract($largeContainerBuffer, 1_048_576)['items']) !== 70_000) {
    throw new RuntimeException('Protocol container was truncated by the former per-container ceiling.');
}

$partial = substr($encoded, 0, FrameCodec::HEADER_BYTES - 1);
$unchanged = $partial;
if (FrameCodec::extract($partial, 1_048_576) !== null || $partial !== $unchanged) {
    throw new RuntimeException('Partial binary header was consumed.');
}
$buffer = $encoded . $encoded;
$decoded = FrameCodec::extract($buffer, 1_048_576);
if (!is_array($decoded) || $decoded['minimum'] !== PHP_INT_MIN || $decoded['maximum'] !== PHP_INT_MAX
    || $decoded['negative'] !== -123456789 || $decoded['float'] !== -123.5
    || !($decoded['bytes'] instanceof BinaryValue) || $decoded['bytes']->bytes !== $bytes
    || !($decoded['list'][3] instanceof BinaryValue) || $decoded['list'][3]->bytes !== "\x01\x02") {
    throw new RuntimeException('Typed binary frame did not round trip.');
}
if (FrameCodec::extract($buffer, 1_048_576) === null || $buffer !== '') {
    throw new RuntimeException('Concatenated binary frames were not extracted independently.');
}

$stream = fopen('php://temp', 'w+b');
fwrite($stream, $encoded);
rewind($stream);
$blocking = FrameCodec::read($stream, 1_048_576);
fclose($stream);
if (!($blocking['bytes'] instanceof BinaryValue) || $blocking['bytes']->bytes !== $bytes) {
    throw new RuntimeException('Blocking binary frame read failed.');
}

$tampered = $encoded;
$tampered[strlen($tampered) - 1] = chr(ord($tampered[strlen($tampered) - 1]) ^ 1);
$expectProtocolError(static function () use ($tampered): void {
    $buffer = $tampered;
    FrameCodec::extract($buffer, 1_048_576);
});
$wrongVersion = $encoded;
$wrongVersion[4] = chr(1);
$expectProtocolError(static function () use ($wrongVersion): void {
    $buffer = $wrongVersion;
    FrameCodec::extract($buffer, 1_048_576);
});
$expectProtocolError(static function (): void {
    $buffer = pack('N', 15) . '{"type":"ping"}';
    FrameCodec::extract($buffer, 1_048_576);
});
$expectProtocolError(static fn() => FrameCodec::encode(['bad' => "\xff"], 1_048_576));
$expectProtocolError(static fn() => FrameCodec::encode(['' => null], 1_048_576));
$expectProtocolError(static fn() => FrameCodec::encode(['bytes' => new BinaryValue(str_repeat('x', 2_000))], 1_024), [
    'FRAME_TOO_LARGE',
]);
$expectProtocolError(static fn() => FrameCodec::encode(['type' => 'ping'], 0), ['INVALID_CONFIG']);
$expectProtocolError(static fn() => FrameCodec::encode([1, 2, 3], 1_048_576));

$stream = fopen('php://temp', 'w+b');
fwrite($stream, substr($encoded, 0, FrameCodec::HEADER_BYTES + 1));
rewind($stream);
$expectProtocolError(static fn() => FrameCodec::read($stream, 1_048_576));
fclose($stream);

$duplicateMap = chr(8) . pack('N', 2)
    . pack('N', 1) . 'x' . chr(0)
    . pack('N', 1) . 'x' . chr(0);
$duplicateFrame = $frame($duplicateMap);
$expectProtocolError(static function () use ($duplicateFrame): void {
    $buffer = $duplicateFrame;
    FrameCodec::extract($buffer, 1_048_576);
});
$trailingFrame = $frame(chr(8) . pack('N', 1) . pack('N', 4) . 'type'
    . chr(5) . pack('N', 1) . 'x' . chr(0));
$expectProtocolError(static function () use ($trailingFrame): void {
    $buffer = $trailingFrame;
    FrameCodec::extract($buffer, 1_048_576);
});
$emptyMapFrame = $frame(chr(8) . pack('N', 1) . pack('N', 4) . 'data' . chr(8) . pack('N', 0));
$expectProtocolError(static function () use ($emptyMapFrame): void {
    $buffer = $emptyMapFrame;
    FrameCodec::extract($buffer, 1_048_576);
});

echo "protocol: ok\n";
