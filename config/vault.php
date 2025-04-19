<?php

declare(strict_types = 1);

return [
    'url' => env('VAULT_URL', config('app.url') . '/vault'),
    'issuer' => env('VAULT_ISSUER', config('app.url')),
    'client_id' => env('VAULT_CLIENT_ID', 'vault-client-id'),

    'token_expiration_time' => 60, // 1 minute
    'cache_ttl' => 60 * 60, // 1 hour
];
