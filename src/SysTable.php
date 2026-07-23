<?php

declare(strict_types=1);

namespace FoxyDB;

use FoxyDB\Protocol\FrameCodec;

final class SysTable
{
    private static ?float $serverStartTime = null;

    public static function columns(): array
    {
        return [
            ['name' => 'variable_name', 'type' => 'VARCHAR', 'length' => 128],
            ['name' => 'value', 'type' => 'VARCHAR', 'length' => 255],
        ];
    }

    public static function setStartTime(float $time): void
    {
        self::$serverStartTime = $time;
    }

    public static function select(Config $config): ExecutionResult
    {
        $uptime = self::$serverStartTime !== null
            ? microtime(true) - self::$serverStartTime
            : 0.0;

        $rows = [
            ['variable_name' => 'version', 'value' => '0.1.0'],
            ['variable_name' => 'foxydb_version', 'value' => '0.1.0'],
            ['variable_name' => 'protocol_version', 'value' => (string) FrameCodec::VERSION],
            ['variable_name' => 'php_version', 'value' => PHP_VERSION],
            ['variable_name' => 'os', 'value' => PHP_OS],
            ['variable_name' => 'architecture', 'value' => PHP_INT_SIZE === 8 ? '64-bit' : '32-bit'],
            ['variable_name' => 'hostname', 'value' => php_uname('n')],
            ['variable_name' => 'server_time', 'value' => date('Y-m-d H:i:s')],
            ['variable_name' => 'uptime_seconds', 'value' => (string) (int) $uptime],
            ['variable_name' => 'memory_usage_bytes', 'value' => (string) memory_get_usage()],
            ['variable_name' => 'memory_peak_usage_bytes', 'value' => (string) memory_get_peak_usage()],
        ];

        $rusage = getrusage();
        if (isset($rusage['ru_utime.tv_sec'])) {
            $rows[] = [
                'variable_name' => 'cpu_user_seconds',
                'value' => (string) ($rusage['ru_utime.tv_sec'] + $rusage['ru_utime.tv_usec'] / 1_000_000),
            ];
            $rows[] = [
                'variable_name' => 'cpu_system_seconds',
                'value' => (string) ($rusage['ru_stime.tv_sec'] + $rusage['ru_stime.tv_usec'] / 1_000_000),
            ];
        }

        $rows[] = ['variable_name' => 'max_connections', 'value' => (string) $config->maxConnections];
        $rows[] = ['variable_name' => 'max_frame_bytes', 'value' => (string) $config->maxFrameBytes];
        $rows[] = ['variable_name' => 'idle_timeout_seconds', 'value' => (string) $config->idleTimeoutSeconds];

        return ExecutionResult::rows(['variable_name', 'value'], $rows);
    }
}
