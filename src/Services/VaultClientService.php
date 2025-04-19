<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultException;
use JuniorFontenele\LaravelVaultClient\Models\Key;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;
use VaultJWT;

class VaultClientService
{
    public function getPublicKey(string $kid): ?string
    {
        return Cache::remember('vault:kid:' . $kid, config('vault.cache_ttl', 3600), function () use ($kid) {
            $url = rtrim(config('vault.url'), '/') . '/kms/' . $kid;

            $response = Http::acceptJson()->get($url);

            if ($response->failed()) {
                Log::error('Failed to get public key', [
                    'kid' => $kid,
                    'url' => $url,
                    'status' => $response->status(),
                    'response' => $response->body(),
                ]);

                return null;
            }

            return $response->json()->get('public_key');
        });
    }

    /**
     * Rotate the private key.
     *
     * @return PrivateKey
     */
    public function rotateKey(): PrivateKey
    {
        $privateKey = PrivateKey::getPrivateKey();

        if (empty($privateKey)) {
            throw new VaultException('No valid key found for the client.');
        }

        $scope = ['keys:rotate'];

        $token = VaultJWT::sign($privateKey, $scope);

        $url = rtrim(config('vault.url'), '/') . '/kms/' . $privateKey->id . '/rotate';

        $response = Http::acceptJson()
            ->withToken($token)
            ->post($url);

        if ($response->failed()) {
            Log::error('Failed to rotate the key', [
                'kid' => $privateKey->id,
                'url' => $url,
                'status' => $response->status(),
                'response' => $response->json(),
            ]);

            throw new VaultException('Failed to rotate the key: ' . $response->json('error') ?? 'Unknown error');
        }

        $data = $response->json();

        $newKey = PrivateKey::create([
            'id' => $data['kid'],
            'client_id' => $data['client_id'],
            'private_key' => $data['private_key'],
            'public_key' => $data['public_key'],
            'version' => $data['version'],
            'valid_from' => $data['valid_from'],
            'valid_until' => $data['valid_until'],
        ]);

        $privateKey->revoke();

        return $newKey;
    }
}
