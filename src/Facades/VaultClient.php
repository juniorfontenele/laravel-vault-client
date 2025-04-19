<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Facades;

use Illuminate\Support\Facades\Facade;
use JuniorFontenele\LaravelVaultClient\Services\VaultClientService;

class VaultClient extends Facade
{
    protected static function getFacadeAccessor()
    {
        return VaultClientService::class;
    }
}
