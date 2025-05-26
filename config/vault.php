<?php

declare(strict_types = 1);

return [
    'url' => env('VAULT_URL', 'http://localhost/vault'),
    'issuer' => env('VAULT_ISSUER', 'http://localhost'),
    'client_id' => env('VAULT_CLIENT_ID'),
    'provisioning_token' => env('VAULT_PROVISIONING_TOKEN'),

    'token_expiration_time' => 60, // 1 minute
    'cache_ttl' => 60 * 60, // 1 hour
    'nonce_ttl' => 60 * 60 * 24, // 1 day
    'blacklist_ttl' => 60 * 60 * 24 * 30, // 30 days
];
