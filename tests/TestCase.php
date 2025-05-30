<?php

declare(strict_types = 1);

namespace JuniorFontenele\LaravelVaultClient\Tests;

use Illuminate\Config\Repository;
use Illuminate\Database\Schema\Blueprint;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

use function Orchestra\Testbench\workbench_path;

class TestCase extends OrchestraTestCase
{
    protected $enablesPackageDiscoveries = false;

    protected bool $loadWorkbenchMigrations = false;

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpDatabase($this->app);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
    }

    /**
     * @param  \Illuminate\Foundation\Application  $app
     * @return array
     */
    protected function getPackageProviders($app)
    {
        return [
            \JuniorFontenele\LaravelSecureJwt\Providers\LaravelSecureJwtServiceProvider::class,
            \JuniorFontenele\LaravelVaultClient\Providers\LaravelVaultClientServiceProvider::class,
        ];
    }

    /**
     * Set up the environment.
     *
     * @param  \Illuminate\Foundation\Application  $app
     */
    protected function defineEnvironment($app)
    {
        // Setup environment, like app configuration
        tap($app['config'], function (Repository $config) {
            $config->set('app.timezone', 'UTC');
            $config->set('app.locale', 'en');
            $config->set('app.fallback_locale', 'en');
            $config->set('app.url', 'https://example.com');

            $config->set('database.default', 'sqlite');
            $config->set('database.connections.sqlite', [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
            ]);

            $config->set('vault.client_id', 'test-client-id');
            $config->set('vault.url', 'https://vault.example.com');
            $config->set('vault.issuer', 'https://vault.example.com');
            $config->set('vault.migrations.table_prefix', 'vault_');
        });
    }

    /**
     * Set up the database.
     *
     * @param  \Illuminate\Foundation\Application  $app
     */
    protected function setUpDatabase($app)
    {
        $schema = $app['db']->connection()->getSchemaBuilder();

        // Create tables

        $schema->create('users', function (Blueprint $table) {
            $table->increments('id');
            $table->string('email');
        });
    }

    protected function defineDatabaseMigrations()
    {
        if (! $this->loadWorkbenchMigrations) {
            return;
        }

        $this->loadMigrationsFrom(
            workbench_path('database/migrations')
        );
    }

    protected function getLaravelVersion()
    {
        return (float) app()->version();
    }
}
