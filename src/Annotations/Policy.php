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
namespace FirecmsExt\Auth\Annotations;

use Hyperf\Di\Annotation\AbstractAnnotation;
use InvalidArgumentException;

/**
 * @Annotation
 * @Target("CLASS")
 * @Attributes({
 *     @Attribute("models", type="array")
 * })
 */
class Policy extends AbstractAnnotation
{
    /**
     * @var string[]
     */
    public array $models;

    public function __construct($value = null)
    {
        parent::__construct($value);
        if (isset($value['value'])) {
            $value['value'] = empty($value['value']) ? [] : (is_array($value['value']) ? array_unique($value['value']) : [$value['value']]);
            if (empty($value['value'])) {
                throw new InvalidArgumentException('Policy annotation requires at least one model.');
            }
            $this->models = $value['value'];
        }
    }
}
