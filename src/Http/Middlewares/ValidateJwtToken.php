<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Http\Middlewares;

use Closure;
use Illuminate\Http\Request;
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;
use Throwable;

class ValidateJwtToken
{
    public function handle(Request $request, Closure $next, ...$scopes)
    {
        try {
            $token = $request->bearerToken();

            if (empty($token)) {
                return response()->json(['error' => 'Token not provided'], 401);
            }

            $kid = VaultClient::getKidFromJwt($token);

            if (empty($kid)) {
                return response()->json(['error' => 'Kid not found in JWT'], 401);
            }

            $key = VaultClient::findByKid($kid);

            if (empty($key)) {
                return response()->json(['error' => 'Public key not found for kid: ' . $kid], 401);
            }

            if ($key->isInvalid()) {
                return response()->json(['error' => 'Public key is expired, revoked or not valid yet'], 401);
            }

            $decodedJwt = VaultClient::decode($token, $key->public_key);

            $payload = (array) $decodedJwt;

            // Validate nonce
            // Check blacklisted token

            if ($payload['client_id'] !== $key->client_id) {
                return response()->json(['error' => 'Invalid client_id'], 401);
            }

            if ($scopes !== []) {
                $scopes = array_map('strtolower', $scopes);

                $tokenScopes = explode(' ', $payload['scope'] ?? '');

                foreach ($scopes as $scope) {
                    if (! in_array($scope, $tokenScopes)) {
                        return response()->json(['error' => 'Insufficient scope'], 403);
                    }
                }
            }

            return $next($request);
        } catch (Throwable $e) {
            return response()->json([
                'error' => 'Invalid token',
                'error' => $e->getMessage(),
            ], 401);
        }
    }
}
