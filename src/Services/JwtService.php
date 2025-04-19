<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Str;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultException;
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;

class JwtService
{
    public function sign(PrivateKey $privateKey, ?array $scope = [], array $claims = [], array $headers = []): string
    {
        $headers['kid'] = $privateKey->id;

        $claims = array_merge([
            'iss' => config('vault.issuer'),
            'client_id' => config('vault.client_id'),
            'nonce' => bin2hex(random_bytes(16)),
            'iat' => time(),
            'exp' => time() + config('vault.token_expiration_time', 60),
            'jti' => (string) Str::uuid(),
        ], $claims);

        if (! empty($scope)) {
            $claims['scope'] = implode(' ', $scope);
        }

        return JWT::encode($claims, $privateKey->private_key, 'RS256', $headers['kid'], $headers);
    }

    public function validate(string $jwt): object
    {
        $kid = $this->getKidFromJwt($jwt);

        if (empty($kid)) {
            throw new VaultException('Kid not found in JWT');
        }

        $publicKey = VaultClient::getPublicKey($kid);

        if (empty($publicKey)) {
            throw new VaultException('Public key not found for kid: ' . $kid);
        }

        return $this->decode($jwt, $publicKey);
    }

    public function getKidFromJwt(string $jwt): ?string
    {
        $header = json_decode(base64_decode(explode('.', $jwt)[0]), true);

        return $header['kid'] ?? null;
    }

    public function decode(string $jwt, string $keyMaterial, string $algorithm = 'RS256'): object
    {
        return JWT::decode($jwt, new Key($keyMaterial, $algorithm));
    }
}
