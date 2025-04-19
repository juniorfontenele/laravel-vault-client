<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultException;
use JuniorFontenele\LaravelVaultClient\Models\Client;
use JuniorFontenele\LaravelVaultClient\Models\Key;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;
use phpseclib3\Crypt\RSA;

class KeyPairService
{
    /**
     * Rotate a key.
     *
     * @param Key $key
     * @return array{0: Key, 1: string}
     */
    public function rotate(Key $key, int $expiresIn = 365): array
    {
        return DB::transaction(function () use ($key, $expiresIn) {
            [$publicKey, $privateKey] = $this->generateKeyPair();

            $newKey = $key->client->keys()->create([
                'public_key' => $publicKey,
                'valid_from' => now(),
                'valid_until' => now()->addDays($expiresIn),
                'revoked' => false,
            ]);

            $key->revoke();

            Event::dispatch('vault.key.rotated', [$key, $newKey]);

            return [$newKey, $privateKey];
        });
    }

    /**
     * Create a new key for a client.
     *
     * @param Client $client
     * @param int $bits
     * @param int $expiresIn
     * @return array{0: Key, 1: string}
     */
    public function createKeyForClient(Client $client, int $bits = 2048, int $expiresIn = 365): array
    {
        [$publicKey, $privateKey] = $this->generateKeyPair($bits);

        return DB::transaction(function () use ($client, $publicKey, $privateKey, $expiresIn) {
            $client->keys()->valid()->each(fn (Key $key) => $this->revokeKey($key));

            $key = $client->keys()->create([
                'public_key' => $publicKey,
                'valid_from' => now(),
                'valid_until' => now()->addDays($expiresIn),
                'revoked' => false,
            ]);

            Event::dispatch('vault.key.created', [$key]);

            return [$key, $privateKey];
        });
    }

    /**
     * Generate a new key pair.
     *
     * @return array{0: string, 1: string}
     */
    public function generateKeyPair(int $bits = 2048): array
    {
        $privateKey = RSA::createKey($bits);

        return [
            $privateKey->getPublicKey()->toString('PKCS8'),
            $privateKey->toString('PKCS8'),
        ];
    }

    /**
     * Find a key by its KID.
     *
     * @param string $kid
     * @return Key|null
     */
    public function findByKid(string $kid): ?Key
    {
        Event::dispatch('vault.key.findByKid', [$kid]);

        return Key::query()->valid()->where('id', $kid)->first();
    }

    public function findByClientId(string $clientId): ?Key
    {
        Event::dispatch('vault.key.findByClientId', [$clientId]);

        $client = Client::query()
            ->active()
            ->where('id', $clientId)
            ->first();

        if (empty($client)) {
            return null;
        }

        return $client->key;
    }

    /**
     * Revoke a key.
     * @param Key $key
     * @return bool
     */
    public function revokeKey(Key $key): bool
    {
        $key->revoke();

        Event::dispatch('vault.key.revoked', [$key->refresh()]);

        return true;
    }

    /**
     * Delete a key.
     * @param Key $key
     * @return bool
     */
    public function deleteKey(Key $key): bool
    {
        $key->delete();

        Event::dispatch('vault.key.deleted', [$key]);

        return true;
    }

    /**
     * Cleanup expired keys.
     * @return int Number of expired keys deleted
     */
    public function cleanupExpiredKeys(): int
    {
        $expired = Key::query()->expired()->get();

        if ($expired->isEmpty()) {
            return 0;
        }

        foreach ($expired as $key) {
            $key->delete();
        }

        Event::dispatch('vault.key.cleanupExpired', [$expired]);

        return $expired->count();
    }

    /**
     * Cleanup revoked keys.
     * @return int Number of revoked keys deleted
     */
    public function cleanupRevokedKeys(): int
    {
        $revoked = Key::query()->revoked()->get();

        if ($revoked->isEmpty()) {
            return 0;
        }

        foreach ($revoked as $key) {
            $key->delete();
        }

        Event::dispatch('vault.key.cleanupRevoked', [$revoked]);

        return $revoked->count();
    }

    public function loadPrivateKey(): string
    {
        $privateKey = PrivateKey::getPrivateKey();

        if (empty($privateKey)) {
            throw new VaultException('Private key not found');
        }

        return $privateKey->private_key;
    }
}
