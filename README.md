# Laravel Vault Client

[![Latest Version on Packagist](https://img.shields.io/packagist/v/juniorfontenele/laravel-vault-client.svg?style=flat-square)](https://packagist.org/packages/juniorfontenele/laravel-vault-client)
[![Tests](https://img.shields.io/github/actions/workflow/status/juniorfontenele/laravel-vault-client/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/juniorfontenele/laravel-vault-client/actions/workflows/tests.yml)
[![Total Downloads](https://img.shields.io/packagist/dt/juniorfontenele/laravel-vault-client.svg?style=flat-square)](https://packagist.org/packages/juniorfontenele/laravel-vault-client)

Laravel Vault Client is a client for Laravel Vault Server provided by `juniorfontenele/laravel-vault-server` package for secure key management, key rotation, JWT signing/validation, and secure user hash storage.

## Installation

Install via composer:

```bash
composer require juniorfontenele/laravel-vault-client
```

Publish and run the migrations:

```bash
php artisan vault:install
```

## Artisan Commands

- `php artisan vault:install` — Publish and run the migrations.
- `php artisan vault:provision {token}` — Provision the client in Vault using the provision token.
- `php artisan vault:rotate` — Rotate the client's private key.

## Usage Examples

### Rotate Private Key

```php
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

$newKey = VaultClient::rotateKey();
```

### Get Public Key by Key ID

```php
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

$publicKey = VaultClient::getPublicKey($kid);
```

### Get User Hash

```php
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

$hash = VaultClient::getHashForUser($userId);
```

### Store User Password (hash will be generated)

```php
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

VaultClient::storePasswordForUser($userId, $password);
```

### Store User Hash (provide your own hash)

```php
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

VaultClient::storeHashForUser($userId, $hash);
```

### Delete User Hash

```php
use JuniorFontenele\LaravelVaultClient\Facades\VaultClient;

VaultClient::deleteHashForUser($userId);
```

### Protecting Routes with JWT Middleware

You can protect your routes using the `vault.jwt` middleware:

```php
use Illuminate\Support\Facades\Route;

Route::middleware(['vault.jwt'])->group(function () {
    // Your protected routes here
});
```

You may also pass scopes as optional parameters to the middleware:

```php
Route::middleware(['vault.jwt:admin'])->get('/admin', ...);
```

## Configuration

The configuration file `config/vault.php` will be published with all required options, such as `client_id`, `url`, `issuer`, TTLs, etc.

## Testing

```bash
composer test
```

## Credits

- [Junior Fontenele](https://github.com/juniorfontenele)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). See [License File](LICENSE.md) for more information.
