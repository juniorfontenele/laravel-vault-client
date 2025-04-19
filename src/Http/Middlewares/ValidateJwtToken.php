<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Http\Middlewares;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use JuniorFontenele\LaravelVaultClient\Exceptions\JwtException;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultException;
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

class ValidateJwtToken
{
    public function handle(Request $request, Closure $next, ...$scopes)
    {
        try {
            $token = $request->bearerToken();

            if (empty($token)) {
                return response()->json(['error' => 'Token not provided'], 401);
            }

            VaultClient::validate($token, $scopes);

            return $next($request);
        } catch (JwtException $e) {
            Log::error('Validate JWT failed', [
                'error' => 'Token validation failed',
                'message' => $e->getMessage(),
            ]);

            return response()->json([
                'error' => 'Token validation failed',
                'message' => $e->getMessage(),
            ], 401);
        } catch (VaultException $e) {
            Log::error('Validate JWT failed', [
                'error' => 'Vault validation failed',
                'message' => $e->getMessage(),
            ]);

            return response()->json([
                'error' => 'Vault validation failed',
                'message' => $e->getMessage(),
            ], 401);
        } catch (\Exception $e) {
            Log::error('Validate JWT failed', [
                'error' => 'Unexpected error',
                'message' => $e->getMessage(),
            ]);

            return response()->json([
                'error' => 'Unexpected error',
                'message' => $e->getMessage(),
            ], 401);
        }
    }
}
