<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Artisan;
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if ($this->canAutoProvision()) {
            Artisan::call('vault:provision', [
                'token' => config('vault.provisioning_token'),
            ]);
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
