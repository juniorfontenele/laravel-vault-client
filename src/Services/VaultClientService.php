<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use JuniorFontenele\LaravelVaultClient\Enums\Permission;
use JuniorFontenele\LaravelVaultClient\Exceptions\JwtException;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultException;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;

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

        $scope = [Permission::KEYS_ROTATE->value];

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

            throw new VaultException('Failed to rotate the key: ' . ($response->json('error') ?? 'Unknown error'));
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

    /**
     * Sign the JWT token.
     *
     * @param PrivateKey $privateKey
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     * @param array<string> $scope
     * @return string
     */
    public function sign(PrivateKey $privateKey, ?array $scope = [], array $claims = [], array $headers = []): string
    {
        /** @var string $kid */
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

    public function validate(string $jwt, $scopes = []): void
    {
        $decodedJwt = $this->decode($jwt);

        $payload = (array) $decodedJwt;

        if (empty($payload['nonce'])) {
            throw new JwtException('Nonce not found in JWT');
        }

        if (Cache::has('vault:nonce:' . $payload['nonce'])) {
            throw new JwtException('Nonce already used');
        }

        if (empty($payload['jti'])) {
            throw new JwtException('JTI not found in JWT');
        }

        if (Cache::has('vault:jti:' . $payload['jti'])) {
            throw new JwtException('Token is blacklisted');
        }

        if ($scopes !== null && $scopes !== []) {
            $scopes = array_map('strtolower', $scopes);

            $tokenScopes = explode(' ', $payload['scope'] ?? '');

            foreach ($scopes as $scope) {
                if (! in_array($scope, $tokenScopes)) {
                    throw new JwtException('Insufficient scope');
                }
            }
        }

        Cache::put('vault:nonce:' . $payload['nonce'], true, $payload['exp'] - time());
        Cache::put('vault:jti:' . $payload['jti'], true, $payload['exp'] - time());
    }

    public function getKidFromJwtString(string $jwt): ?string
    {
        $header = json_decode(base64_decode(explode('.', $jwt)[0]), true);

        return $header['kid'] ?? null;
    }

    public function decode(string $jwt): object
    {
        $kid = $this->getKidFromJwtString($jwt);

        if (! $kid) {
            throw new JwtException('Kid not found in JWT');
        }

        $key = $this->getPublicKey($kid);

        if (! $key) {
            throw new VaultException('Public key not found for kid: ' . $kid);
        }

        $decodedJwt = JWT::decode($jwt, new Key($key['public_key'], 'RS256'));
        $payload = (array) $decodedJwt;

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

    public function getHashForUser(string $userId): ?string
    {
        $url = $this->vaultUrl . '/hash/' . $userId;

        $privateKey = $this->loadPrivateKey();
        $scope = [Permission::HASHES_READ->value];
        $token = $this->sign($privateKey, $scope);

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
        $scope = [Permission::HASHES_CREATE->value];
        $token = $this->sign($privateKey, $scope);

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

    public function deleteHashForUser(string $userId): bool
    {
        $privateKey = $this->loadPrivateKey();
        $scope = [Permission::HASHES_DELETE->value];
        $token = $this->sign($privateKey, $scope);

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
}
