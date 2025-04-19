<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Facades;

use Illuminate\Support\Facades\Facade;
use JuniorFontenele\LaravelVaultClient\Services\ClientManagerService;

class VaultClientManager extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return ClientManagerService::class;
    }
}
