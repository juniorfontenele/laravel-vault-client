<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;

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
    public function handle(): void
    {
        $clientId = config('vault.client_id');

        if (empty($clientId)) {
            $this->error('Client ID is not set in the configuration.');

            return;
        }

        $provisionToken = $this->argument('token') ?? text(
            'Enter the provision token',
            required: true,
        );

        if (empty($provisionToken)) {
            $this->error('Provision token is required.');

            return;
        }

        if (! preg_match('/^[a-f0-9]{32}$/', $provisionToken)) {
            $this->error('Invalid provision token format. It should be a 32-character hexadecimal string.');

            return;
        }

        $url = config('vault.url') . "/client/{$clientId}/provision";

        $response = Http::acceptJson()->post($url, [
            'provision_token' => $provisionToken,
        ]);

        if ($response->failed()) {
            $this->error('Failed to provision the client. Please check the token and try again.');
            Log::error('Failed to provision the client.', [
                'status' => $response->status(),
                'response' => $response->json(),
            ]);

            if ($response->json('error')) {
                $this->error('Error: ' . $response->json('error'));
            }

            exit(static::FAILURE);
        }

        $data = $response->json();

        PrivateKey::create([
            'id' => $data['kid'],
            'client_id' => $clientId,
            'private_key' => $data['private_key'],
            'public_key' => $data['public_key'],
            'version' => $data['version'],
            'valid_from' => $data['valid_from'],
            'valid_until' => $data['valid_until'],
        ]);

        $this->info('Client provisioned successfully.');
    }
}
