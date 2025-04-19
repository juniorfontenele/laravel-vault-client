<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Enums;

enum Permission: string
{
    case KEYS_READ = 'keys:read';
    case KEYS_ROTATE = 'keys:rotate';
    case HASHES_READ = 'hashes:read';
    case HASHES_CREATE = 'hashes:create';
    case HASHES_DELETE = 'hashes:delete';

    public static function toArray(): array
    {
        $permissions = [];
        $cases = self::cases();

        foreach ($cases as $case) {
            $permissions[$case->value] = $case->getLabel();
        }

        return $permissions;
    }

    public function getLabel(): string
    {
        return match ($this) {
            self::KEYS_READ => 'Read Keys',
            self::KEYS_ROTATE => 'Rotate Keys',
            self::HASHES_READ => 'Read Hashes',
            self::HASHES_CREATE => 'Create Hashes',
        };
    }
}
