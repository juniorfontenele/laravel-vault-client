<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Log;
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if ($this->canAutoProvision()) {
            try {
                VaultClient::provisionClient(config('vault.provisioning_token'));

                Log::info('Vault client auto-provisioned successfully.');
            } catch (Throwable $e) {
                Log::error('Failed to auto-provision vault client: ' . $e->getMessage());
            }
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        //
    }

    protected function canAutoProvision(): bool
    {
        return (! empty(config('vault.provisioning_token')))
        && (! empty(config('vault.client_id')))
        && (! VaultClient::privateKeyExists());
    }
};
