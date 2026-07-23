<?php

declare(strict_types=1);

namespace FoxyDB\Exception;

use RuntimeException;

final class FoxyException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly string $errorCode = 'FOXY_ERROR',
        public readonly array $details = [],
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public function toArray(): array
    {
        $error = [
            'code' => $this->errorCode,
            'message' => $this->getMessage(),
        ];

        if ($this->details !== []) {
            $error['details'] = $this->details;
        }

        return $error;
    }
}
