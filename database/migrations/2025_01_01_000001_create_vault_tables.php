<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $tablePrefix = config('vault.migrations.table_prefix', 'vault_');

        Schema::create($tablePrefix . 'private_keys', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->uuid('client_id')->index();
            $table->longText('private_key');
            $table->longText('public_key');
            $table->unsignedBigInteger('version')->index();
            $table->boolean('revoked')->index()->default(false);
            $table->timestamp('valid_from');
            $table->timestamp('valid_until');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        $tablePrefix = config('vault.migrations.table_prefix', 'vault_');

        Schema::dropIfExists($tablePrefix . 'private_keys');
    }
};
