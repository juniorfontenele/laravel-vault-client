<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultException;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;

class VaultClientService
{
    public function __construct(public string $clientId, public string $vaultUrl, public string $issuer, public int $cacheTtl = 3600)
    {
        $this->vaultUrl = rtrim($this->vaultUrl, '/');
    }

    public function getPublicKey(string $kid): ?string
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

            return $response->json('public_key');
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

        $scope = ['keys:rotate'];

        $token = $this->sign($privateKey, $scope);

        $url = $this->vaultUrl . '/kms/' . $privateKey->id . '/rotate';

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

    public function sign(PrivateKey $privateKey, ?array $scope = [], array $claims = [], array $headers = []): string
    {
        $kid = $privateKey->id;
        $headers['kid'] = $kid;

        $claims = array_merge([
            'iss' => config('vault.issuer'),
            'client_id' => config('vault.client_id'),
            'nonce' => bin2hex(random_bytes(16)),
            'iat' => time(),
            'exp' => time() + config('vault.token_expiration_time', 60),
            'jti' => (string) Str::uuid(),
        ], $claims);

        if ($scope !== null && $scope !== []) {
            $claims['scope'] = implode(' ', $scope);
        }

        return JWT::encode($claims, $privateKey->private_key, 'RS256', $headers['kid'], $headers);
    }

    public function validate(string $jwt): object
    {
        $kid = $this->getKidFromJwtString($jwt);

        if ($kid === null || $kid === '' || $kid === '0') {
            throw new VaultException('Kid not found in JWT');
        }

        $publicKey = $this->getPublicKey($kid);

        if ($publicKey === null || $publicKey === '' || $publicKey === '0') {
            throw new VaultException('Public key not found for kid: ' . $kid);
        }

        return $this->decode($jwt, $publicKey);
    }

    public function getKidFromJwtString(string $jwt): ?string
    {
        $header = json_decode(base64_decode(explode('.', $jwt)[0]), true);

        return $header['kid'] ?? null;
    }

    public function decode(string $jwt, string $publicKeyString, string $algorithm = 'RS256'): object
    {
        return JWT::decode($jwt, new Key($publicKeyString, $algorithm));
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

        if (!$privateKey instanceof \JuniorFontenele\LaravelVaultClient\Models\PrivateKey) {
            throw new VaultException('No valid key found for the client.');
        }

        return $privateKey;
    }
}
