<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Models;

use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use JuniorFontenele\LaravelVaultClient\Database\Factories\PrivateKeyFactory;

class PrivateKey extends Model
{
    /** @use HasFactory<PrivateKeyFactory> */
    use HasFactory;
    use HasUuids;

    /** @var list<string> */
    protected $fillable = [
        'id',
        'client_id',
        'private_key',
        'public_key',
        'revoked',
        'version',
        'valid_from',
        'valid_until',
    ];

    protected $hidden = [
        'private_key',
    ];

    protected static function booted(): void
    {
        static::creating(function (self $key) {
            if (empty($key->version)) {
                $maxVersion = static::query()
                    ->where('client_id', $key->client_id)
                    ->max('version') ?? 0;

                $key->version = $maxVersion + 1;
            }
        });
    }

    public function getTable(): string
    {
        return config('vault.migrations.table_prefix', 'vault_') . 'private_keys';
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'private_key' => 'encrypted',
            'revoked' => 'boolean',
            'valid_from' => 'datetime',
            'valid_until' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }

    protected static function newFactory(): PrivateKeyFactory
    {
        return PrivateKeyFactory::new();
    }

    /**
     * Revokes the key.
     * This method sets the revoked attribute to true and saves the model.
     * @return bool
     */
    public function revoke(): bool
    {
        $this->revoked = true;
        $this->revoked_at = now();
        $this->save();

        return true;
    }

    /**
     * Checks if the key is expired.
     * The key is considered expired if the current date is greater than the valid_until date.
     * This method does not check if the key is revoked.
     * @return bool
     */
    public function isExpired(): bool
    {
        return $this->valid_until < now();
    }

    /**
     * Checks if the key is active.
     * The key is considered active if the current date is greater than or equal to the valid_from date.
     * This method does not check if the key is revoked.
     * @return bool
     */
    public function isActive(): bool
    {
        return $this->valid_from <= now();
    }

    /**
     * Checks if the key is revoked.
     * The key is considered revoked if the revoked attribute is true.
     * @return bool
     */
    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    /**
     * Checks if the key is valid.
     * The key is considered valid if it is not revoked, not expired, and active.
     * @return bool
     */
    public function isValid(): bool
    {
        return ! $this->isRevoked()
            && ! $this->isExpired()
            && $this->isActive();
    }

    #[Scope]
    protected function valid(Builder $query): void
    {
        $query->where('revoked', false)
            ->where('valid_until', '>', now())
            ->where('valid_from', '<=', now());
    }

    #[Scope]
    protected function revoked(Builder $query): void
    {
        $query->where('revoked', true);
    }

    #[Scope]
    protected function expired(Builder $query): void
    {
        $query->where('valid_until', '<', now());
    }

    public static function getPrivateKey(): ?static
    {
        return static::query()
            ->valid()
            ->where('client_id', config('vault.client_id'))
            ->orderBy('version', 'desc')
            ->first();
    }
}
