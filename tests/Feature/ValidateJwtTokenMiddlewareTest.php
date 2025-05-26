<?php

declare(strict_types = 1);

use Illuminate\Http\Request;
use JuniorFontenele\LaravelVaultClient\Exceptions\JwtException;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultException;
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;
use JuniorFontenele\LaravelVaultClient\Http\Middlewares\ValidateJwtToken;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;
use JuniorFontenele\LaravelVaultClient\Services\VaultClientService;
use JuniorFontenele\LaravelVaultClient\Tests\TestCase;

uses(TestCase::class);

beforeEach(function () {
    $this->middleware = new ValidateJwtToken();
    $this->loadMigrationsFrom(__DIR__ . '/../../database/migrations');

    $this->vaultClientService = new VaultClientService(
        clientId: 'test-client-id',
        vaultUrl: 'https://vault.example.com',
        issuer: 'https://vault.example.com',
        cacheTtl: 3600
    );

    $this->app->singleton(VaultClientService::class, fn () => $this->vaultClientService);
});

test('it passes request with valid token', function () {
    $privateKey = PrivateKey::factory()->create([
        'client_id' => 'test-client-id',
    ]);

    $token = $this->vaultClientService->sign($privateKey);

    $request = new Request();
    $request->headers->set('Authorization', "Bearer {$token}");

    $wasCalled = false;

    // Mock the validate method to avoid actual validation
    VaultClient::shouldReceive('validate')
        ->once()
        ->with($token, [])
        ->andReturn(true);

    $response = $this->middleware->handle($request, function ($req) use (&$wasCalled) {
        $wasCalled = true;

        return 'passed';
    });

    expect($wasCalled)->toBeTrue();
    expect($response)->toBe('passed');
});

test('it rejects request without token', function () {
    $request = new Request();

    $response = $this->middleware->handle($request, function ($req) {
        return 'should not reach here';
    });

    expect($response->status())->toBe(401);
    expect($response->getData(true))->toBe(['error' => 'Token not provided']);
});

test('it rejects request with invalid jwt token', function () {
    $request = new Request();
    $request->headers->set('Authorization', 'Bearer invalid.token.here');

    VaultClient::shouldReceive('validate')
        ->once()
        ->andThrow(new JwtException('Invalid token format'));

    $response = $this->middleware->handle($request, function ($req) {
        return 'should not reach here';
    });

    expect($response->status())->toBe(401);
    expect($response->getData(true))->toBe([
        'error' => 'Token validation failed',
        'message' => 'Invalid token format',
    ]);
});

test('it rejects request with vault exception', function () {
    $request = new Request();
    $request->headers->set('Authorization', 'Bearer valid.looking.token');

    VaultClient::shouldReceive('validate')
        ->once()
        ->andThrow(new VaultException('Key not found'));

    $response = $this->middleware->handle($request, function ($req) {
        return 'should not reach here';
    });

    expect($response->status())->toBe(401);
    expect($response->getData(true))->toBe([
        'error' => 'Vault validation failed',
        'message' => 'Key not found',
    ]);
});

test('it rejects request with unexpected exception', function () {
    $request = new Request();
    $request->headers->set('Authorization', 'Bearer some.token.value');

    VaultClient::shouldReceive('validate')
        ->once()
        ->andThrow(new Exception('Unexpected error'));

    $response = $this->middleware->handle($request, function ($req) {
        return 'should not reach here';
    });

    expect($response->status())->toBe(401);
    expect($response->getData(true))->toBe([
        'error' => 'Unexpected error',
        'message' => 'Unexpected error',
    ]);
});
