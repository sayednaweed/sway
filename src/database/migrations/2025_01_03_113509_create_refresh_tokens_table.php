<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('refresh_tokens', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('tokenable_id');
            $table->string('tokenable_type');
            $table->text('access_token');
            $table->text('refresh_token');
            $table->timestamp('access_token_expires_at')->default(DB::raw('CURRENT_TIMESTAMP'));
            $table->timestamp('refresh_token_expires_at')->default(DB::raw('CURRENT_TIMESTAMP'));
            $table->timestamps();
            $table->index(['tokenable_id', "tokenable_type"]);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('refresh_tokens');
    }
};
