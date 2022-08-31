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
namespace FirecmsExt\Auth;

use FirecmsExt\Auth\Access\GateManager;
use FirecmsExt\Auth\Commands\GenAuthPolicyCommand;
use FirecmsExt\Auth\Contracts\Access\GateManagerInterface;
use FirecmsExt\Auth\Contracts\AuthManagerInterface;
use FirecmsExt\Auth\Contracts\PasswordBrokerManagerInterface;
use FirecmsExt\Auth\Passwords\PasswordBrokerManager;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
                AuthManagerInterface::class => AuthManager::class,
                GateManagerInterface::class => GateManager::class,
                PasswordBrokerManagerInterface::class => PasswordBrokerManager::class,
            ],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                    'ignore_annotations' => [
                        'mixin',
                    ],
                ],
            ],
            'commands' => [
                GenAuthPolicyCommand::class,
            ],
            'publish' => [
                [
                    'id' => 'config',
                    'description' => 'The config for firecms-ext/auth.',
                    'source' => __DIR__ . '/../publish/auth.php',
                    'destination' => BASE_PATH . '/config/autoload/auth.php',
                ],
                [
                    'id' => 'migration',
                    'description' => 'The migration for firecms-ext/auth.',
                    'source' => __DIR__ . '/../publish/migrations/2022_08_12_000000_create_users_table.php',
                    'destination' => BASE_PATH . '/migrations/2022_08_12_000000_create_users_table.php',
                ],
                [
                    'id' => 'model',
                    'description' => 'The model for firecms-ext/auth.',
                    'source' => __DIR__ . '/../publish/User.php',
                    'destination' => BASE_PATH . '/app/Model/User.php',
                ],
            ],
        ];
    }
}
