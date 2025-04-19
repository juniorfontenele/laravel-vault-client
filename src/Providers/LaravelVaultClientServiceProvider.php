<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Providers;

use Illuminate\Foundation\AliasLoader;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use JuniorFontenele\LaravelVaultClient\Console\Commands\VaultInstallCommand;
use JuniorFontenele\LaravelVaultClient\Console\Commands\VaultKeyRotateCommand;
use JuniorFontenele\LaravelVaultClient\Console\Commands\VaultProvisionClientCommand;
use JuniorFontenele\LaravelVaultClient\Facades\VaultClientManager;
use JuniorFontenele\LaravelVaultClient\Facades\VaultJWT;
use JuniorFontenele\LaravelVaultClient\Facades\VaultKey;
use JuniorFontenele\LaravelVaultClient\Http\Middlewares\ValidateJwtToken;
use JuniorFontenele\LaravelVaultClient\Services\KeyPairService;
use JuniorFontenele\LaravelVaultClient\Services\VaultClientService;

class LaravelVaultClientServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../../database/migrations');
        $this->publishes([
            __DIR__ . '/../../database/migrations' => database_path('migrations'),
        ], 'migrations');

        $this->publishes([
            __DIR__ . '/../../config/vault.php' => config_path('vault.php'),
        ], 'config');

        $this->app->singleton(KeyPairService::class, function ($app) {
            return new KeyPairService();
        });

        $loader = AliasLoader::getInstance();
        $loader->alias('VaultKey', VaultKey::class);
        $loader->alias('VaultClientManager', VaultClientManager::class);
        $loader->alias('VaultJWT', VaultJWT::class);
        $loader->alias('VaultClient', VaultClientService::class);

        /** @var Router $router */
        $router = app('router');
        $router->aliasMiddleware('vault.jwt', ValidateJwtToken::class);
    }

    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/vault.php', 'vault');

        if ($this->app->runningInConsole()) {
            $this->commands([
                VaultInstallCommand::class,
                VaultProvisionClientCommand::class,
                VaultKeyRotateCommand::class,
            ]);
        }
    }
}
