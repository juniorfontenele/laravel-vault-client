<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Console\Commands;

use Illuminate\Console\Command;
use JuniorFontenele\LaravelVaultClient\Exceptions\VaultClientProvisioningException;
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

use function Laravel\Prompts\text;

class VaultProvisionClientCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'vault:provision 
        {token? : Provision token} 
    ';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Provision application';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $clientId = config('vault.client_id');

        if (empty($clientId)) {
            $this->error('Client ID is not set in the configuration.');

            return static::FAILURE;
        }

        $provisionToken = $this->argument('token') ?? text(
            'Enter the provision token',
            required: true,
        );

        if (empty($provisionToken)) {
            $this->error('Provision token is required.');

            return static::FAILURE;
        }

        if (! preg_match('/^[a-f0-9]{32}$/', $provisionToken)) {
            $this->error('Invalid provision token format. It should be a 32-character hexadecimal string.');

            return static::FAILURE;
        }

        try {
            VaultClient::provisionClient($provisionToken);
        } catch (VaultClientProvisioningException $e) {
            $this->error('Failed to provision client: ' . $e->getMessage());

            return static::FAILURE;
        } catch (\Exception $e) {
            $this->error('An unexpected error occurred: ' . $e->getMessage());

            return static::FAILURE;
        }

        $this->info('Client provisioned successfully.');

        return static::SUCCESS;
    }
}
