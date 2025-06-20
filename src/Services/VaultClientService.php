<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use JuniorFontenele\LaravelSecureJwt\CustomClaims;
use JuniorFontenele\LaravelSecureJwt\Facades\SecureJwt;
use JuniorFontenele\LaravelSecureJwt\JwtKey;
use JuniorFontenele\LaravelSecureJwt\SecureJwt as SecureJwtObject;
use JuniorFontenele\LaravelVaultClient\Exceptions\JwtException;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultClientProvisioningException;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultException;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultKeyException;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;
use Throwable;

class VaultClientService
{
    public function __construct(public string $clientId, public string $vaultUrl, public string $issuer, public int $cacheTtl = 3600)
    {
        $this->vaultUrl = rtrim($this->vaultUrl, '/');
    }

    public function getPublicKey(string $kid): ?array
    {
        return Cache::remember('vault:kid:' . $kid, $this->cacheTtl, function () use ($kid) {
            $url = $this->vaultUrl . '/kms/' . $kid;

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

            return $response->json() ?? null;
        });
    }

    /**
     * Rotate the private key.
     *
     * @return PrivateKey
     */
    public function rotateKey(): PrivateKey
    {
        $privateKey = $this->loadPrivateKey();

        $token = $this->sign($privateKey);

        $url = $this->vaultUrl . '/kms/rotate';

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

            throw new VaultKeyException($response->json('error') ?? 'Unknown error');
        }

        $data = $response->json();

        $newKey = PrivateKey::create([
            'id' => $data['key_id'],
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

    /**
     * Sign the JWT token.
     *
     * @param PrivateKey $privateKey
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     * @return string
     */
    public function sign(PrivateKey $privateKey, array $claims = []): string
    {
        /** @var string $kid */
        $kid = $privateKey->id;

        $mergedClaims = array_merge([
            'client_id' => $this->clientId,
        ], $claims);

        $customClaims = new CustomClaims($mergedClaims);

        return SecureJwt::encode(
            $customClaims,
            new JwtKey($kid, $privateKey->private_key, 'RS256'),
        );
    }

    public function getKidFromJwtString(string $jwt): ?string
    {
        $header = json_decode(base64_decode(explode('.', $jwt)[0]), true);

        return $header['kid'] ?? null;
    }

    public function decode(string $jwt): SecureJwtObject
    {
        $kid = $this->getKidFromJwtString($jwt);

        if (! $kid) {
            throw new JwtException('Kid not found in JWT');
        }

        $key = $this->getPublicKey($kid);

        if (! $key) {
            throw new VaultException('Public key not found for kid: ' . $kid);
        }

        $decodedJwt = SecureJwt::decode($jwt, new JwtKey($kid, $key['public_key'], 'RS256'));
        $payload = $decodedJwt->payload();

        if ($payload['client_id'] !== $key['client_id']) {
            throw new JwtException('Invalid client_id');
        }

        return $decodedJwt;
    }

    /**
     * Load the private key from the database.
     *
     * @throws VaultException
     *
     * @return PrivateKey
     */
    public function loadPrivateKey(): PrivateKey
    {
        $privateKey = PrivateKey::getPrivateKey();

        if (! $privateKey instanceof PrivateKey) {
            throw new VaultException('No valid key found for the client.');
        }

        return $privateKey;
    }

    public function privateKeyExists(): bool
    {
        try {
            $this->loadPrivateKey();

            return true;
        } catch (Throwable $e) {
            return false;
        }
    }

    public function getHashForUser(string $userId): ?string
    {
        $url = $this->vaultUrl . '/hash/' . $userId;

        $privateKey = $this->loadPrivateKey();
        $token = $this->sign($privateKey);

        $response = Http::acceptJson()->withToken($token)->get($url);

        if ($response->failed()) {
            Log::error('Failed to get user hash', [
                'user_id' => $userId,
                'url' => $url,
                'status' => $response->status(),
                'response' => $response->body(),
            ]);

            return null;
        }

        return $response->json('hash') ?? null;
    }

    public function storePasswordForUser(string $userId, string $password): bool
    {
        $privateKey = $this->loadPrivateKey();
        $token = $this->sign($privateKey);

        $url = $this->vaultUrl . '/hash/' . $userId;
        $response = Http::acceptJson()->withToken($token)->post($url, [
            'hash' => bcrypt($password),
        ]);

        if ($response->failed()) {
            Log::error('Failed to store user hash', [
                'user_id' => $userId,
                'url' => $url,
                'status' => $response->status(),
                'response' => $response->json(),
            ]);

            return false;
        }

        return true;
    }

    public function storeHashForUser(string $userId, string $hash): bool
    {
        $privateKey = $this->loadPrivateKey();
        $token = $this->sign($privateKey);

        $url = $this->vaultUrl . '/hash/' . $userId;
        $response = Http::acceptJson()->withToken($token)->post($url, [
            'hash' => $hash,
        ]);

        if ($response->failed()) {
            Log::error('Failed to store user hash', [
                'user_id' => $userId,
                'url' => $url,
                'status' => $response->status(),
                'response' => $response->json(),
            ]);

            return false;
        }

        return true;
    }

    public function deleteHashForUser(string $userId): bool
    {
        $privateKey = $this->loadPrivateKey();
        $token = $this->sign($privateKey);

        $url = $this->vaultUrl . '/hash/' . $userId;
        $response = Http::acceptJson()->withToken($token)->delete($url);

        if ($response->failed()) {
            Log::error('Failed to delete user hash', [
                'user_id' => $userId,
                'url' => $url,
                'status' => $response->status(),
                'response' => $response->json(),
            ]);

            return false;
        }

        return true;
    }

    public function checkPasswordForUser(string $userId, string $password): bool
    {
        $hash = $this->getHashForUser($userId);

        if (! $hash) {
            return false;
        }

        return password_verify($password, $hash);
    }

    public function provisionClient(string $provisionToken): PrivateKey
    {
        $url = $this->vaultUrl . '/client/' . $this->clientId . '/provision';

        $response = Http::acceptJson()->post($url, [
            'provision_token' => $provisionToken,
        ]);

        if ($response->failed()) {
            throw new VaultClientProvisioningException($response->json('error') ?? 'Unknown error');
        }

        $data = $response->json();

        return PrivateKey::create([
            'id' => $data['key_id'],
            'client_id' => $this->clientId,
            'private_key' => $data['private_key'],
            'public_key' => $data['public_key'],
            'version' => $data['version'],
            'valid_from' => $data['valid_from'],
            'valid_until' => $data['valid_until'],
        ]);
    }
}
