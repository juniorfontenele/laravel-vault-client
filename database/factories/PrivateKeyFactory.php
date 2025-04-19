<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use JuniorFontenele\LaravelVaultClient\Models\PrivateKey;
use phpseclib3\Crypt\RSA;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<PrivateKey>
 */
class PrivateKeyFactory extends Factory
{
    protected $model = PrivateKey::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $privateKey = RSA::createKey(2048);
        $publicKey = $privateKey->getPublicKey();

        return [
            'client_id' => $this->faker->uuid(),
            'private_key' => $privateKey->toString('PKCS8'),
            'public_key' => $publicKey->toString('PKCS8'),
            'version' => 1,
            'revoked' => false,
            'valid_from' => now(),
            'valid_until' => now()->addDays(30),
        ];
    }
}
