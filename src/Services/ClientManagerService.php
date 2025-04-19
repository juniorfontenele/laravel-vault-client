<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Services;

use Illuminate\Support\Facades\Event;
use JuniorFontenele\LaravelVaultClient\Models\Client;

class ClientManagerService
{
    /**
     * Create a new client.
     *
     * @param string $name
     * @param array<int, string> $allowedScopes
     * @param string $description
     * @return Client
     */
    public function createClient(string $name, array $allowedScopes = [], string $description = ''): Client
    {
        $provisionToken = bin2hex(random_bytes(16));

        $client = Client::create([
            'name' => $name,
            'allowed_scopes' => $allowedScopes,
            'description' => $description,
            'provision_token' => bcrypt($provisionToken),
        ]);

        Event::dispatch('vault.client.created', [$client]);

        $client->provision_token = $provisionToken;

        return $client;
    }

    /**
     * Delete a client.
     *
     * @param Client $client
     * @return bool
     */
    public function deleteClient(Client $client): bool
    {
        $client->delete();

        Event::dispatch('vault.client.deleted', [$client]);

        return true;
    }

    /**
     * Cleanup inactive clients.
     *
     * @return int
     */
    public function cleanupInactiveClients(): int
    {
        $deletedClients = Client::query()->inactive()->get();
        $countDeleted = $deletedClients->count();

        if ($countDeleted === 0) {
            return 0;
        }

        Client::query()->inactive()->delete();

        Event::dispatch('vault.client.cleanup', [$deletedClients]);

        return $deletedClients;
    }
}
