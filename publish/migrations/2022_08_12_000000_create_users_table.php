<?php

declare(strict_types=1);
/**
 * This file is part of FirecmsExt Auth.
 *
 * @link     https://www.klmis.cn
 * @document https://www.klmis.cn
 * @contact  zhimengxingyun@klmis.cn
 * @license  https://github.com/firecms-ext/auth/blob/master/LICENSE
 */
use Hyperf\Database\Migrations\Migration;
use Hyperf\Database\Schema\Blueprint;
use Hyperf\Database\Schema\Schema;

class CreateUsersTable extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            // $table->id();
            $table->unsignedBigInteger('id')->primary();

            $table->string('username')->unique()->comment('登录账号');
            $table->string('password')->nullable()->comment('登录密码');

            $table->boolean('enable')->default(true)->comment('启用');

            $table->dateTime('created_at')->comment('创建时间')->nullable();
            $table->dateTime('updated_at')->comment('更新时间')->nullable();
            $table->dateTime('deleted_at')->comment('删除时间')->nullable();

            $table->comment('系统-用户表');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
}
