<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Console\Commands;

use Illuminate\Console\Command;
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;

class VaultKeyRotateCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'vault:rotate 
        {--force : Force rotation without confirmation}
    ';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Rotate the key';

    /**
     * Execute the console command.
     */
    public function handle(): void
    {
        $clientId = config('vault.client_id');

        if (empty($clientId)) {
            $this->error('Client ID is not set in the configuration.');

            return;
        }

        $privateKey = PrivateKey::getPrivateKey();

        try {
            VaultClient::rotateKey();
        } catch (\Exception $e) {
            $this->error('Failed to rotate the key: ' . $e->getMessage());

            exit(static::FAILURE);
        }

        $privateKey->revoke();

        $this->info('Private key rotated successfully.');
    }
}
