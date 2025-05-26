<?php

declare(strict_types = 1);

use Illuminate\Support\Facades\Http;
use JuniorFontenele\LaravelVaultClient\Exceptions\JwtException;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultClientProvisioningException;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultKeyException;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;
use JuniorFontenele\LaravelVaultClient\Services\VaultClientService;
use JuniorFontenele\LaravelVaultClient\Tests\TestCase;
use phpseclib3\Crypt\RSA;

uses(TestCase::class);

beforeEach(function () {
    $this->vaultUrl = 'https://vault.example.com';
    $this->clientId = 'test-client-id';
    $this->issuer = 'https://vault.example.com';

    $this->vaultClientService = new VaultClientService(
        clientId: $this->clientId,
        vaultUrl: $this->vaultUrl,
        issuer: $this->issuer,
        cacheTtl: 3600
    );

    // Create needed database tables
    $this->loadMigrationsFrom(__DIR__ . '/../../database/migrations');

    $privateKey = RSA::createKey(2048);
    $this->privateKey = $privateKey->toString('PKCS8');
    $this->publicKey = $privateKey->getPublicKey()->toString('PKCS8');
});

test('it gets public key from vault', function () {
    $kid = 'test-key-id';
    $expectedResponse = [
        'key_id' => $kid,
        'client_id' => $this->clientId,
        'public_key' => $this->publicKey,
    ];

    Http::fake([
        "$this->vaultUrl/kms/$kid" => Http::response($expectedResponse, 200),
    ]);

    $result = $this->vaultClientService->getPublicKey($kid);

    expect($result)->toBe($expectedResponse);
    Http::assertSent(function ($request) use ($kid) {
        return $request->url() === "$this->vaultUrl/kms/$kid" &&
            $request->method() === 'GET';
    });
});

test('it returns null when public key fetch fails', function () {
    $kid = 'test-key-id';

    Http::fake([
        "$this->vaultUrl/kms/$kid" => Http::response(['error' => 'Key not found'], 404),
    ]);

    $result = $this->vaultClientService->getPublicKey($kid);

    expect($result)->toBeNull();
});

test('it can rotate key', function () {
    $privateKey = PrivateKey::factory()->create([
        'client_id' => $this->clientId,
        'id' => 'original-key-id',
    ]);

    $newKeyResponse = [
        'key_id' => 'new-key-id',
        'client_id' => $this->clientId,
        'private_key' => $this->privateKey,
        'public_key' => $this->publicKey,
        'version' => 2,
        'valid_from' => now()->toISOString(),
        'valid_until' => now()->addYear()->toISOString(),
    ];

    Http::fake([
        "$this->vaultUrl/kms/original-key-id/rotate" => Http::response($newKeyResponse, 200),
    ]);

    $result = $this->vaultClientService->rotateKey();

    expect($result)->toBeInstanceOf(PrivateKey::class);
    expect($result->id)->toBe('new-key-id');
    expect($result->version)->toBe(2);

    // Check that the original key was revoked
    expect($privateKey->refresh()->isRevoked())->toBeTrue();
});

test('it throws exception when key rotation fails', function () {
    PrivateKey::factory()->create([
        'client_id' => $this->clientId,
        'id' => 'original-key-id',
    ]);

    Http::fake([
        "$this->vaultUrl/kms/original-key-id/rotate" => Http::response([
            'error' => 'Rotation failed',
        ], 400),
    ]);

    expect(fn () => $this->vaultClientService->rotateKey())
        ->toThrow(VaultKeyException::class);
});

test('it can sign jwt tokens', function () {
    $privateKey = PrivateKey::factory()->create([
        'client_id' => $this->clientId,
    ]);

    $token = $this->vaultClientService->sign($privateKey, ['custom' => 'claim']);

    expect($token)->toBeString();
    expect($token)->toContain('.');
    expect(explode('.', $token))->toHaveCount(3); // JWT format: header.payload.signature
});

test('it can extract kid from jwt string', function () {
    $kidValue = 'test-key-id';
    $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kidValue]));
    $payload = base64_encode(json_encode(['sub' => '1234']));
    $signature = 'fake_signature';

    $jwt = "$header.$payload.$signature";

    $extractedKid = $this->vaultClientService->getKidFromJwtString($jwt);

    expect($extractedKid)->toBe($kidValue);
});

test('it can decode valid jwt token', function () {
    $kid = 'test-key-id';
    $privateKey = PrivateKey::factory()->create([
        'id' => $kid,
        'client_id' => $this->clientId,
    ]);

    $jwt = $this->vaultClientService->sign($privateKey, ['custom' => 'claim']);

    Http::fake([
        "$this->vaultUrl/kms/$kid" => Http::response([
            'key_id' => $kid,
            'client_id' => $this->clientId,
            'public_key' => $privateKey->public_key,
        ], 200),
    ]);

    $decodedJwt = $this->vaultClientService->decode($jwt);

    expect($decodedJwt->payload()['client_id'])->toBe($this->clientId);
    expect($decodedJwt->payload()['custom'])->toBe('claim');
});

test('it throws exception when decoding jwt without kid', function () {
    $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT'])); // No kid
    $payload = base64_encode(json_encode(['sub' => '1234']));
    $signature = 'fake_signature';

    $jwt = "$header.$payload.$signature";

    expect(fn () => $this->vaultClientService->decode($jwt))
        ->toThrow(JwtException::class, 'Kid not found in JWT');
});

test('it can check if private key exists', function () {
    // No key exists yet
    expect($this->vaultClientService->privateKeyExists())->toBeFalse();

    // Create key
    PrivateKey::factory()->create([
        'client_id' => $this->clientId,
    ]);

    // Now key exists
    expect($this->vaultClientService->privateKeyExists())->toBeTrue();
});

test('it can get hash for user', function () {
    $userId = 'user123';
    $expectedHash = 'hashed_password_123';
    $privateKey = PrivateKey::factory()->create([
        'client_id' => $this->clientId,
    ]);

    Http::fake([
        "$this->vaultUrl/hash/$userId" => Http::response([
            'hash' => $expectedHash,
        ], 200),
    ]);

    $result = $this->vaultClientService->getHashForUser($userId);

    expect($result)->toBe($expectedHash);
});

test('it returns null when getting hash fails', function () {
    $userId = 'user123';
    PrivateKey::factory()->create([
        'client_id' => $this->clientId,
    ]);

    Http::fake([
        "$this->vaultUrl/hash/$userId" => Http::response(['error' => 'Not found'], 404),
    ]);

    $result = $this->vaultClientService->getHashForUser($userId);

    expect($result)->toBeNull();
});

test('it can store password for user', function () {
    $userId = 'user123';
    $password = 'secure_password';
    $privateKey = PrivateKey::factory()->create([
        'client_id' => $this->clientId,
    ]);

    Http::fake([
        "$this->vaultUrl/hash/$userId" => Http::response(['success' => true], 200),
    ]);

    $result = $this->vaultClientService->storePasswordForUser($userId, $password);

    expect($result)->toBeTrue();
    Http::assertSent(function ($request) use ($userId) {
        return $request->url() === "$this->vaultUrl/hash/$userId" &&
               $request->method() === 'POST' &&
               isset($request->data()['hash']);
    });
});

test('it can store hash for user', function () {
    $userId = 'user123';
    $hash = 'already_hashed_password';
    $privateKey = PrivateKey::factory()->create([
        'client_id' => $this->clientId,
    ]);

    Http::fake([
        "$this->vaultUrl/hash/$userId" => Http::response(['success' => true], 200),
    ]);

    $result = $this->vaultClientService->storeHashForUser($userId, $hash);

    expect($result)->toBeTrue();
    Http::assertSent(function ($request) use ($userId, $hash) {
        return $request->url() === "$this->vaultUrl/hash/$userId" &&
               $request->method() === 'POST' &&
               $request->data()['hash'] === $hash;
    });
});

test('it can delete hash for user', function () {
    $userId = 'user123';
    $privateKey = PrivateKey::factory()->create([
        'client_id' => $this->clientId,
    ]);

    Http::fake([
        "$this->vaultUrl/hash/$userId" => Http::response(['success' => true], 200),
    ]);

    $result = $this->vaultClientService->deleteHashForUser($userId);

    expect($result)->toBeTrue();
    Http::assertSent(function ($request) use ($userId) {
        return $request->url() === "$this->vaultUrl/hash/$userId" &&
               $request->method() === 'DELETE';
    });
});

test('it can check password for user', function () {
    $userId = 'user123';
    $password = 'correct_password';
    $hash = password_hash($password, PASSWORD_DEFAULT);

    $privateKey = PrivateKey::factory()->create([
        'client_id' => $this->clientId,
    ]);

    Http::fake([
        "$this->vaultUrl/hash/$userId" => Http::response([
            'hash' => $hash,
        ], 200),
    ]);

    // With correct password
    $result = $this->vaultClientService->checkPasswordForUser($userId, $password);
    expect($result)->toBeTrue();

    // With incorrect password
    $result = $this->vaultClientService->checkPasswordForUser($userId, 'wrong_password');
    expect($result)->toBeFalse();
});

test('it can provision client', function () {
    $provisionToken = md5('test_token');
    $responseData = [
        'key_id' => 'new-key-id',
        'client_id' => $this->clientId,
        'private_key' => $this->privateKey,
        'public_key' => $this->publicKey,
        'version' => 1,
        'valid_from' => now()->toISOString(),
        'valid_until' => now()->addYear()->toISOString(),
    ];

    Http::fake([
        "$this->vaultUrl/client/{$this->clientId}/provision" => Http::response($responseData, 200),
    ]);

    $result = $this->vaultClientService->provisionClient($provisionToken);

    expect($result)->toBeInstanceOf(PrivateKey::class);
    expect($result->id)->toBe('new-key-id');
    expect($result->client_id)->toBe($this->clientId);
    expect($result->version)->toBe(1);

    Http::assertSent(function ($request) use ($provisionToken) {
        return $request->data()['provision_token'] === $provisionToken;
    });
});

test('it throws exception when provision fails', function () {
    $provisionToken = md5('test_token');

    Http::fake([
        "$this->vaultUrl/client/{$this->clientId}/provision" => Http::response([
            'error' => 'Invalid token',
        ], 400),
    ]);

    expect(fn () => $this->vaultClientService->provisionClient($provisionToken))
        ->toThrow(VaultClientProvisioningException::class);
});
