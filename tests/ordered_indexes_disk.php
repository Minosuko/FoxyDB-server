<?php

declare(strict_types=1);

require dirname(__DIR__) . '/src/Autoloader.php';

use FoxyDB\Config;
use FoxyDB\Storage\IndexStore;
use FoxyDB\Support\BinaryCodec;
use FoxyDB\Support\FileSystem;

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'foxydb-ordisk-' . bin2hex(random_bytes(6));

$store = null;
try {
    $config = new Config('127.0.0.1', 2002, $directory);
    $root = $directory . DIRECTORY_SEPARATOR . 'indexes';
    $store = new IndexStore($root, $config);

    $store->prepare(['shard']);
    $snapshotPath = $root . DIRECTORY_SEPARATOR . 'shard' . DIRECTORY_SEPARATOR . 'ordered.fxo';

    $count = 8500;
    $valueOf = static fn(int $value): string => str_pad((string) $value, 5, '0', STR_PAD_LEFT)
        . str_repeat('p', 3_984 + $value % 17);
    $keyOf = static fn(int $value): string => IndexStore::orderedKey([$valueOf($value)]);

    $expected = [];
    foreach (range(0, $count - 1) as $value) {
        $expected[$value] = [$value + 1];
    }

    $pending = [];
    $records = 0;
    foreach (range(0, $count - 1) as $value) {
        $pending[] = [true, $keyOf($value), $value + 1];
        $records++;
        if ($records % 500 === 0) {
            foreach ($pending as [$put, $key, $rowId]) {
                $store->batchAppend('shard', $key, $rowId, $put);
            }
            $store->flushBatch();
            $pending = [];
        }
    }
    foreach ($pending as [$put, $key, $rowId]) {
        $store->batchAppend('shard', $key, $rowId, $put);
    }
    $store->flushBatch();

    if (is_file($snapshotPath)) {
        throw new RuntimeException('Snapshot was built before any range lookup.');
    }

    $range = static function (IndexStore $instance, ?int $low, ?int $high, bool $lowInc, bool $highInc) use ($keyOf): array {
        $ids = $instance->rangeLookup(
            'shard',
            $low === null ? null : $keyOf($low),
            $high === null ? null : $keyOf($high),
            $lowInc,
            $highInc,
        );
        sort($ids, SORT_NUMERIC);
        return $ids;
    };

    $expectedAfter = static function (array $mirror, ?int $low, ?int $high, bool $lowInc, bool $highInc) use ($valueOf): array {
        $ids = [];
        foreach ($mirror as $value => $rowIds) {
            $inRange = ($low === null || $value > $low || ($lowInc && $value === $low))
                && ($high === null || $value < $high || ($highInc && $value === $high));
            if ($inRange) {
                array_push($ids, ...$rowIds);
            }
        }
        sort($ids, SORT_NUMERIC);
        return $ids;
    };

    $cases = [
        [null, $count - 1, true, true],
        [0, $count - 1, true, true],
        [100, 200, true, true],
        [100, 200, false, true],
        [100, 200, true, false],
        [100, 200, false, false],
        [2500, 6000, true, true],
        [4000, null, true, true],
        [3999, null, false, true],
    ];
    foreach ($cases as [$low, $high, $lowInc, $highInc]) {
        $actual = $range($store, $low, $high, $lowInc, $highInc);
        $want = $expectedAfter($expected, $low, $high, $lowInc, $highInc);
        if ($actual !== $want) {
            throw new RuntimeException(
                sprintf(
                    'Disk-backed range mismatch for [%s..%s] inc=(%s,%s).',
                    json_encode($low),
                    json_encode($high),
                    json_encode($lowInc),
                    json_encode($highInc),
                )
                . "\nExpected: " . json_encode($want) . "\nActual: " . json_encode($actual),
            );
        }
    }

    if (!is_file($snapshotPath)) {
        throw new RuntimeException('Disk-backed snapshot was not materialized.');
    }
    $snapshot = file_get_contents($snapshotPath);
    if (!is_string($snapshot) || BinaryCodec::readUint32($snapshot, 4) !== 2) {
        throw new RuntimeException('Checksummed ordered snapshot version was not written.');
    }
    $corrupt = $snapshot;
    $corrupt[strlen($corrupt) - 1] = chr(ord($corrupt[strlen($corrupt) - 1]) ^ 1);
    file_put_contents($snapshotPath, $corrupt);
    try {
        (new IndexStore($root, $config))->rangeLookup('shard', null, null, true, true);
        throw new RuntimeException('Corrupt ordered snapshot block was accepted.');
    } catch (\FoxyDB\Exception\FoxyException $exception) {
        if ($exception->errorCode !== 'STORAGE_CORRUPT') {
            throw $exception;
        }
    } finally {
        file_put_contents($snapshotPath, $snapshot);
    }

    $duplicateValue = 1;
    $store->batchAppend('shard', $keyOf($duplicateValue), 90000, true);
    $store->flushBatch();
    $expected[$duplicateValue][] = 90000;

    foreach (range(0, $count - 1) as $value) {
        if ($value % 100 !== 0) {
            continue;
        }
        $store->batchAppend('shard', $keyOf($value), $value + 1, false);
    }
    $store->flushBatch();
    foreach ($expected as $value => &$rowIds) {
        if ($value % 100 === 0) {
            if (($key = array_search($value + 1, $rowIds, true)) !== false) {
                unset($rowIds[$key]);
            }
        }
    }
    unset($rowIds);

    $store->batchAppend('shard', $keyOf(5), 6, false);
    $store->batchAppend('shard', $keyOf(99999), 6, true);
    $store->flushBatch();
    if (($key = array_search(6, $expected[5], true)) !== false) {
        unset($expected[5][$key]);
    }
    $expected[99999] = [6];

    $actual = $range($store, 0, $count - 1, true, true);
    $want = $expectedAfter($expected, 0, $count - 1, true, true);
    if ($actual !== $want) {
        throw new RuntimeException(
            "Disk-backed ranges diverged after updates and deletes.\n"
            . 'Expected: ' . json_encode($want) . "\nActual: " . json_encode($actual),
        );
    }

    if (85 !== count(array_filter($range($store, 0, $count - 1, true, true), static fn(int $id): bool => $id % 100 === 0 && $id !== 90000))) {
        throw new RuntimeException('Deleted rows reappeared in the disk-backed range.');
    }

    $store->prepare(['small']);
    $smallPath = $root . DIRECTORY_SEPARATOR . 'small' . DIRECTORY_SEPARATOR . 'ordered.fxo';
    $store->batchAppend('small', $keyOf(1), 1, true);
    $store->batchAppend('small', $keyOf(2), 2, true);
    $store->flushBatch();
    if ($store->rangeLookup('small', $keyOf(1), $keyOf(2), true, true) !== [1, 2]) {
        throw new RuntimeException('Small ordered index misbehaved.');
    }
    if (is_file($smallPath)) {
        throw new RuntimeException('Small ordered index incorrectly took the disk-backed path.');
    }

    $store->reset();
    if (is_file($snapshotPath)) {
        throw new RuntimeException('reset() did not remove the snapshot file.');
    }
    if ($range($store, 0, $count - 1, true, true) !== []) {
        throw new RuntimeException('Reset index returned stale rows.');
    }

    echo "ordered indexes disk: ok\n";
} finally {
    if (isset($store)) {
        $store->reset();
    }
    if (is_dir($directory)) {
        FileSystem::removeTree($directory);
    }
}
