<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Http\Controllers;

use JuniorFontenele\LaravelVaultClient\Facades\VaultKey;
use JuniorFontenele\LaravelVaultClient\Http\Resources\KeyResource;

class KmsController
{
    public function show(string $kid)
    {
        $key = VaultKey::findByKid($kid);

        if (! $key) {
            return response()->json([
                'message' => 'No key found.',
            ], 404);
        }

        return $key->toResource(KeyResource::class);
    }

    public function rotate(string $kid)
    {
        $key = VaultKey::findByKid($kid);

        if (! $key) {
            return response()->json([
                'message' => 'No key found.',
            ], 404);
        }

        [$newKey, $privateKey] = VaultKey::rotate($key);

        $newKey->private_key = $privateKey;

        return $newKey->toResource(KeyResource::class);
    }
}
